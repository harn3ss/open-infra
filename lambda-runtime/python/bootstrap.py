#!/usr/bin/env python3
# open-infra Lambda runtime shim (Python) — the "runtime interface" half of the
# runtime-base-image + handler-shim ingestion model (kind: Function spec.code).
#
# A user ships handler CODE (a Zip/source), not a container. open-infra runs it on
# THIS prebuilt base image: the handler is unpacked into /var/task (by a ConfigMap
# mount or an init-container that fetches+unzips the code bucket object), and this
# shim imports the declared handler and serves it over HTTP — turning the Lambda
# handler(event, context) model into the request-driven HTTP service Knative expects.
#
# Contract (stdlib only — no third-party deps, so the base image stays lean):
#   OPENINFRA_HANDLER = "<module>.<function>"  e.g. "app.handler" -> app.py:handler
#   /var/task         = the handler code root (on sys.path)
#   PORT              = listen port (default 8080; Knative sets this)
#
# Invocation model:
#   - POST with a JSON body  -> that JSON is the `event` (direct-invoke, like
#     `aws lambda invoke` with a payload). Non-JSON body -> event={"body": <raw>}.
#   - The request's HTTP facts are always attached at event["_http"]
#     {method, path, headers, query} so HTTP-triggered handlers can use them.
#   - Handler return:
#       * a dict carrying "statusCode" -> used as the HTTP response verbatim
#         (API-Gateway proxy shape: statusCode/headers/body),
#       * anything else -> 200 with the value JSON-encoded.
#   - An unhandled handler exception -> 502 {errorType, errorMessage} + stderr log,
#     never a silent 200.
import importlib
import json
import os
import sys
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TASK_DIR = os.environ.get("OPENINFRA_TASK_DIR", "/var/task")
PORT = int(os.environ.get("PORT", "8080"))
_START = time.time()


class LambdaContext:
    """A minimal AWS Lambda context object (the fields handlers actually read)."""

    def __init__(self):
        self.aws_request_id = str(uuid.uuid4())
        self.function_name = os.environ.get("OPENINFRA_FUNCTION_NAME", "function")
        self.function_version = "$LATEST"
        self.memory_limit_in_mb = int(os.environ.get("OPENINFRA_MEMORY_MB", "0")) or 128
        self.invoked_function_arn = ""
        # Knative enforces the real wall-clock timeout; expose a plausible budget.
        self._deadline = time.time() + int(os.environ.get("OPENINFRA_TIMEOUT_S", "300"))

    def get_remaining_time_in_millis(self):
        return max(0, int((self._deadline - time.time()) * 1000))


OPT_DIR = os.environ.get("OPENINFRA_OPT_DIR", "/opt")  # Lambda layer root (AWS extracts layers here)


def _s3_client():
    """A boto3 S3 client wired for MinIO / any S3-compatible gateway (path-style addressing when a
    custom AWS_ENDPOINT_URL is set; untouched on real AWS). boto3 is imported lazily so the
    inline-ConfigMap path never pays for it."""
    import boto3
    from botocore.config import Config

    endpoint = os.environ.get("AWS_ENDPOINT_URL") or None
    cfg = Config(s3={"addressing_style": "path"}) if endpoint else None
    return boto3.client("s3", endpoint_url=endpoint, config=cfg)


def _fetch_unzip(s3, bucket, key, dest):
    import io
    import zipfile

    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    os.makedirs(dest, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(body)) as z:
        z.extractall(dest)
    sys.stderr.write(f"open-infra-runtime: unpacked s3://{bucket}/{key} ({len(body)} bytes) into {dest}\n")


def _fetch_code():
    """Fetch + unzip the handler .zip into /var/task (the Lambda S3-code model) and any declared
    layers into /opt (the Lambda layer model) at cold start. Creds/endpoint come from the injected
    S3 secret (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_ENDPOINT_URL). A failure here crashes
    the pod (exit 2) rather than serving a broken handler. No-op when the handler is ConfigMap-mounted
    and no layers are declared."""
    bucket = os.environ.get("OPENINFRA_CODE_BUCKET")
    layers_raw = os.environ.get("OPENINFRA_LAYERS", "")
    if not bucket and not layers_raw:
        return  # ConfigMap-mounted (or otherwise pre-populated) /var/task, no layers
    try:
        s3 = _s3_client()
        if bucket:  # the handler zip
            _fetch_unzip(s3, bucket, os.environ.get("OPENINFRA_CODE_KEY", ""), TASK_DIR)
        if layers_raw:  # layers: a JSON list of {bucket, key}, extracted (merged, in order) into /opt
            for layer in json.loads(layers_raw):
                _fetch_unzip(s3, layer["bucket"], layer.get("key", ""), OPT_DIR)
    except Exception:
        sys.stderr.write("open-infra-runtime: failed to fetch/unzip handler or layer code:\n")
        traceback.print_exc()
        sys.exit(2)


def _add_layer_paths():
    """Put the Lambda layer directories on sys.path, the AWS way: a python layer's zip carries a
    `python/` (and/or python/lib/<ver>/site-packages/) tree extracted under /opt, so a handler can
    import modules the layer provides."""
    import glob

    candidates = [os.path.join(OPT_DIR, "python"),
                  os.path.join(OPT_DIR, "python", "lib", "python3.12", "site-packages")]
    candidates += glob.glob(os.path.join(OPT_DIR, "python", "lib", "python*", "site-packages"))
    for p in candidates:
        if os.path.isdir(p) and p not in sys.path:
            sys.path.insert(0, p)


def _load_handler():
    """Import the declared handler once at startup; a bad handler crashes the pod
    (non-zero exit) so the failure is visible, never served as a false 200."""
    spec = os.environ.get("OPENINFRA_HANDLER", "")
    if "." not in spec:
        sys.stderr.write(
            f"open-infra-runtime: OPENINFRA_HANDLER must be '<module>.<function>', got {spec!r}\n"
        )
        sys.exit(2)
    module_name, func_name = spec.rsplit(".", 1)
    if TASK_DIR not in sys.path:
        sys.path.insert(0, TASK_DIR)
    try:
        module = importlib.import_module(module_name)
        return getattr(module, func_name)
    except Exception:
        sys.stderr.write(f"open-infra-runtime: cannot load handler {spec!r} from {TASK_DIR}:\n")
        traceback.print_exc()
        sys.exit(2)


HANDLER = None  # resolved in main()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, body_bytes, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def _handle(self):
        # Health probe (never collides with a real invoke).
        if self.command == "GET" and self.path == "/_openinfra_health":
            self._send(200, b'{"ok":true}')
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            event = json.loads(raw) if raw.strip() else {}
            if not isinstance(event, dict):
                event = {"body": event}
        except Exception:
            event = {"body": raw.decode("utf-8", "replace")}
        # Always surface the HTTP facts for HTTP-triggered handlers.
        q = self.path.split("?", 1)
        event["_http"] = {
            "method": self.command,
            "path": q[0],
            "query": q[1] if len(q) > 1 else "",
            "headers": {k: v for k, v in self.headers.items()},
        }
        try:
            result = HANDLER(event, LambdaContext())
        except Exception as e:
            sys.stderr.write("open-infra-runtime: handler raised:\n")
            traceback.print_exc()
            self._send(502, json.dumps({"errorType": type(e).__name__, "errorMessage": str(e)}).encode())
            return
        # API-Gateway proxy shape -> use verbatim; else 200 + JSON.
        if isinstance(result, dict) and "statusCode" in result:
            status = int(result.get("statusCode", 200))
            body = result.get("body", "")
            if not isinstance(body, (str, bytes)):
                body = json.dumps(body)
            body_bytes = body.encode() if isinstance(body, str) else body
            ctype = (result.get("headers") or {}).get("Content-Type", "application/json")
            self._send(status, body_bytes, ctype)
        else:
            self._send(200, json.dumps(result).encode() if result is not None else b"null")

    def do_POST(self):
        self._handle()

    def do_GET(self):
        self._handle()

    def log_message(self, fmt, *args):  # keep logs quiet/structured
        sys.stderr.write("open-infra-runtime: " + (fmt % args) + "\n")


def main():
    global HANDLER
    _fetch_code()
    _add_layer_paths()  # layer modules importable before the handler loads
    HANDLER = _load_handler()
    sys.stderr.write(
        f"open-infra-runtime: serving {os.environ.get('OPENINFRA_HANDLER')} on :{PORT} "
        f"(task dir {TASK_DIR}, cold-start {time.time() - _START:.3f}s)\n"
    )
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
