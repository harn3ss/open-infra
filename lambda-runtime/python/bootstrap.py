#!/usr/bin/env python3
# open-infra Lambda runtime shim (Python) — the "runtime interface" half of the
# runtime-base-image + handler-shim ingestion model (kind: Function spec.code).
#
# A user ships handler CODE (a Zip/source), not a container. open-infra runs it on
# THIS prebuilt base image: the handler is unpacked into /var/task (by a ConfigMap
# mount, or this shim fetches+unzips the function's stored deployment package or the
# code bucket object at cold start), and this shim imports the declared handler and
# serves it over HTTP — turning the Lambda handler(event, context) model into the
# request-driven HTTP service Knative expects.
#
# Contract (stdlib only — no third-party deps, so the base image stays lean; boto3 is
# imported lazily, for the code bucket and layers alone):
#   OPENINFRA_HANDLER = "<module>.<function>"  e.g. "app.handler" -> app.py:handler
#   /var/task         = the handler code root (on sys.path; OPENINFRA_TASK_DIR overrides)
#   OPENINFRA_CODE_BUCKET / OPENINFRA_CODE_KEY = the handler .zip (S3/MinIO) — optional
#   OPENINFRA_CODE_URL = the function's stored deployment package, served by the aws-shim
#     — optional, never together with OPENINFRA_CODE_BUCKET. Fetched with the function's
#     own identity token, no keys:
#     OPENINFRA_CODE_SHA256     = the package's recorded SHA-256 (64 lowercase hex), checked before unpacking
#     OPENINFRA_CODE_TOKEN_FILE = the projected identity token, sent as "Authorization: Bearer <token>"
#   OPENINFRA_LAYERS  = JSON [{bucket,key}] extracted (merged, in order) into /opt — optional
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
from http.server import BaseHTTPRequestHandler
try:
    from http.server import ThreadingHTTPServer
except ImportError:  # Python 3.6: ThreadingHTTPServer was added in 3.7 — define it the way 3.7 does.
    import socketserver
    from http.server import HTTPServer

    class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
        daemon_threads = True

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

    # Service-scoped AWS_ENDPOINT_URL_S3 first (so the handler's global endpoint isn't forced to the S3
    # gateway); fall back to the legacy global AWS_ENDPOINT_URL.
    endpoint = os.environ.get("AWS_ENDPOINT_URL_S3") or os.environ.get("AWS_ENDPOINT_URL") or None
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


# --- Stored deployment package (OPENINFRA_CODE_URL): Lambda's own model, where the platform keeps the
# function's .zip and the function fetches it with its OWN identity — no keys in the pod. The aws-shim
# serves a pod only its own function's package; the shim may be restarting, so a network error, a 5xx or
# a 429 is retried (5 attempts, 1s/2s/4s/8s apart), while a refusal (400/401/403/404, any other status)
# fails start at once. The token is re-read on every attempt (kubelet rotates it) and never logged.
# stdlib only (urllib + hashlib + zipfile): boto3 is never imported on this path.
_CODE_MAX_BYTES = 64 * 1024 * 1024
_CODE_ATTEMPTS = 5
_CODE_IDLE_S = 30  # an attempt with no bytes for this long is a network error (retried)


class _CodeError(Exception):
    """A start failure whose message says it all: logged alone, without a traceback."""


class _Retryable(Exception):
    """A network failure, a 5xx or a 429 from the code URL: worth another attempt."""


def _read_token(token_file):
    try:
        with open(token_file) as f:
            token = f.read().strip()
    except OSError as e:
        raise _CodeError(f"cannot read OPENINFRA_CODE_TOKEN_FILE {token_file}: {e.strerror or e}")
    if not token:
        raise _CodeError(f"OPENINFRA_CODE_TOKEN_FILE {token_file} is empty: the function's identity token is missing")
    return token


def _get_package_once(opener, code_url, token, tmp):
    """One GET of the package, streamed into tmp while it is hashed and held to the size cap.
    Returns (size, sha256 hex); raises _Retryable for a network failure / 5xx / 429, else _CodeError."""
    import hashlib
    import http.client
    import urllib.error
    import urllib.request

    req = urllib.request.Request(code_url, headers={"Authorization": "Bearer " + token})
    try:
        resp = opener.open(req, timeout=_CODE_IDLE_S)
    except urllib.error.HTTPError as e:  # any non-2xx (redirects are not followed: see _fetch_package)
        try:
            body = e.read(4096).decode("utf-8", "replace")[:200]
        except Exception:
            body = ""
        msg = f"GET {code_url} -> HTTP {e.code}" + (f": {body}" if body else "")
        if e.code >= 500 or e.code == 429:
            raise _Retryable(msg)
        raise _CodeError(msg)
    except (OSError, http.client.HTTPException) as e:  # refused, reset, timed out, name not resolved
        raise _Retryable(str(e) or type(e).__name__)
    with resp:
        status = resp.getcode()
        if status != 200:
            raise _CodeError(f"GET {code_url} -> HTTP {status}")
        declared = resp.headers.get("Content-Length")
        declared = int(declared) if declared and declared.isdigit() else None
        if declared is not None and declared > _CODE_MAX_BYTES:
            raise _CodeError(f"the deployment package is {declared} bytes, over the {_CODE_MAX_BYTES} byte (64 MiB) limit")
        digest = hashlib.sha256()
        size = 0
        with open(tmp, "wb") as out:
            while True:
                try:
                    chunk = resp.read(65536)
                except (OSError, http.client.HTTPException) as e:
                    raise _Retryable(f"the download broke off after {size} bytes: {e}")
                if not chunk:
                    break
                size += len(chunk)
                if size > _CODE_MAX_BYTES:
                    raise _CodeError(f"the deployment package is over the {_CODE_MAX_BYTES} byte (64 MiB) limit")
                digest.update(chunk)
                out.write(chunk)
        # http.client ends a short read quietly rather than raising IncompleteRead: check the length.
        if declared is not None and size != declared:
            raise _Retryable(f"the download broke off after {size} of {declared} bytes")
        return size, digest.hexdigest()


def _unzip_guarded(zip_path, dest):
    """Unpack zip_path into dest, refusing the whole package if any entry is absolute or has a '..'
    segment (zipfile would rewrite such a name and carry on; the package is refused instead)."""
    import zipfile

    root = os.path.realpath(dest)
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            target = os.path.realpath(os.path.join(root, name))
            if (name.startswith(("/", "\\")) or ".." in name.replace("\\", "/").split("/")
                    or (target != root and not target.startswith(root + os.sep))):
                raise _CodeError(f"the deployment package has an entry that would unpack outside {dest}, refused: {name!r}")
        z.extractall(dest)


def _fetch_package(code_url, dest):
    import re
    import tempfile
    import urllib.parse
    import urllib.request

    if not code_url.startswith(("http://", "https://")) or not urllib.parse.urlsplit(code_url).hostname:
        raise _CodeError(f"OPENINFRA_CODE_URL must be an http or https URL, got {code_url!r}")
    want = os.environ.get("OPENINFRA_CODE_SHA256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", want):
        raise _CodeError("OPENINFRA_CODE_URL needs OPENINFRA_CODE_SHA256, the deployment package's recorded SHA-256 "
                         "as 64 lowercase hex characters" + (f"; got {want!r}" if want else "; it is not set"))
    token_file = os.environ.get("OPENINFRA_CODE_TOKEN_FILE", "")
    if not token_file:
        raise _CodeError("OPENINFRA_CODE_URL needs OPENINFRA_CODE_TOKEN_FILE, the path of the function's identity "
                         "token; it is not set")
    _read_token(token_file)  # unreadable or empty fails start before any request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None  # never follow (urllib would carry the Authorization header along): a 3xx fails start

    # No proxy (the token goes to the aws-shim and nowhere else) and no redirects.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
    os.makedirs(dest, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="oi-", suffix=".zip")
    os.close(fd)
    try:
        for attempt in range(1, _CODE_ATTEMPTS + 1):
            try:
                size, got = _get_package_once(opener, code_url, _read_token(token_file), tmp)
                break
            except _Retryable as e:
                if attempt == _CODE_ATTEMPTS:
                    raise _CodeError(f"could not fetch the deployment package from {code_url} in {_CODE_ATTEMPTS} attempts: {e}")
                delay = 2 ** (attempt - 1)  # 1s, 2s, 4s, 8s
                sys.stderr.write(f"open-infra-runtime: fetching the deployment package: {e}; retrying in {delay}s "
                                 f"(attempt {attempt} of {_CODE_ATTEMPTS})\n")
                time.sleep(delay)
        if got != want:
            raise _CodeError(f"the deployment package does not match its recorded SHA-256 (recorded {want[:12]}, fetched {got[:12]})")
        _unzip_guarded(tmp, dest)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    sys.stderr.write(f"open-infra-runtime: unpacked the deployment package ({want[:12]}, {size} bytes) into {dest}\n")


def _fetch_code():
    """Fetch + unzip the handler .zip into /var/task — the function's stored deployment package
    (OPENINFRA_CODE_URL, fetched with the function's identity token) or the code bucket object (the
    Lambda S3-code model) — and any declared layers into /opt (the Lambda layer model) at cold start.
    Bucket/layer creds and endpoint come from the injected S3 secret (AWS_ACCESS_KEY_ID /
    AWS_SECRET_ACCESS_KEY / AWS_ENDPOINT_URL). A failure here crashes the pod (exit 2) rather than
    serving a broken handler. No-op when the handler is ConfigMap-mounted and no layers are declared."""
    bucket = os.environ.get("OPENINFRA_CODE_BUCKET")
    code_url = os.environ.get("OPENINFRA_CODE_URL")
    layers_raw = os.environ.get("OPENINFRA_LAYERS", "")
    if not bucket and not code_url and not layers_raw:
        return  # ConfigMap-mounted (or otherwise pre-populated) /var/task, no layers
    try:
        if code_url and bucket:
            raise _CodeError("OPENINFRA_CODE_URL and OPENINFRA_CODE_BUCKET are both set: a function's deployment "
                             "package comes from one code source (its stored package or an S3 object), not both")
        if code_url:  # the stored deployment package (stdlib only: no boto3)
            _fetch_package(code_url, TASK_DIR)
        if bucket or layers_raw:
            s3 = _s3_client()
            if bucket:  # the handler zip
                _fetch_unzip(s3, bucket, os.environ.get("OPENINFRA_CODE_KEY", ""), TASK_DIR)
            if layers_raw:  # layers: a JSON list of {bucket, key}, extracted (merged, in order) into /opt
                for layer in json.loads(layers_raw):
                    _fetch_unzip(s3, layer["bucket"], layer.get("key", ""), OPT_DIR)
    except _CodeError as e:
        sys.stderr.write(f"open-infra-runtime: {e}\n")
        sys.exit(2)
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

    def _send(self, status, body_bytes, content_type="application/json", extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body_bytes)

    def _read_body(self):
        """The request body, sent with a Content-Length or chunked (HTTP/1.1 Transfer-Encoding), which
        BaseHTTPRequestHandler does not decode: an invocation's payload is the event either way."""
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            out = bytearray()
            while True:
                size = int(self.rfile.readline().split(b";", 1)[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass  # trailers
                    return bytes(out)
                out += self.rfile.read(size)
                self.rfile.readline()  # the CRLF after each chunk
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _handle(self):
        # Health probe (never collides with a real invoke).
        if self.command == "GET" and self.path == "/_openinfra_health":
            self._send(200, b'{"ok":true}')
            return
        raw = self._read_body()
        # Direct-invoke mode (AWS `Invoke` semantics) when the caller sets X-Openinfra-Invoke: direct —
        # the shim's Invoke, open-appsync, and Step Functions all do. The handler's RAW return value is
        # the payload (a {statusCode,...} dict is DATA, never an HTTP mapping), a thrown error is
        # signalled by X-Amz-Function-Error with HTTP still 200, and the event is passed verbatim (no
        # _http). Without the header the legacy API-Gateway proxy mapping applies — API GW callers only.
        direct = self.headers.get("X-Openinfra-Invoke") == "direct"
        try:
            event = json.loads(raw) if raw.strip() else {}
            # Direct: any JSON payload is the event as sent — a list (AppSync's BatchInvoke), a string,
            # null — as Lambda Invoke passes it. Only the proxy mapping needs a dict to carry _http.
            if not direct and not isinstance(event, dict):
                event = {"body": event}
        except Exception:
            event = {"body": raw.decode("utf-8", "replace")}
        if not direct:
            # Surface the HTTP facts for HTTP-triggered (API Gateway) handlers.
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
            err = json.dumps({"errorType": type(e).__name__, "errorMessage": str(e)}).encode()
            if direct:
                self._send(200, err, extra_headers={"X-Amz-Function-Error": "Unhandled"})
            else:
                self._send(502, err)
            return
        if direct:
            # The raw return value IS the payload — never an HTTP proxy mapping.
            self._send(200, json.dumps(result).encode() if result is not None else b"null")
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
