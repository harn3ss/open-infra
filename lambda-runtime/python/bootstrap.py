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
#   OPENINFRA_TIMEOUT_S = the function's Timeout in whole seconds, 1-900; unset, not a whole number
#                       or out of range means 300. Read once at start.
#   PORT              = listen port (default 8080; Knative sets this)
#
# The function's Timeout is enforced here, as Lambda's service enforces it: each invocation's clock
# starts when its request reaches this bootstrap (a cold start, the wait for an instance, is not
# counted, as Lambda does not count init), and context.get_remaining_time_in_millis() counts down to
# that deadline. The handler runs in a worker thread while the request's thread waits for it until the
# deadline, so a handler that blocks (time.sleep, a socket read, a CPU loop in Python code) never holds
# up the answer. An invocation still running at its deadline is answered at once with 504, Content-Type
# application/json and no X-Amz-Function-Error (the aws-shim answers that as Lambda's timeout error),
# the body {"errorType":"Sandbox.Timedout","errorMessage":"RequestId: <id> Error: Task timed out after
# <T>.00 seconds"}; the line "<UTC time> <id> Task timed out after <T>.00 seconds" goes to stdout and,
# for a LogType Tail invoke, into X-Amz-Log-Result before END and a REPORT ending "Status: timeout".
# The handler's result or error arriving later is discarded, never sent. A Python thread cannot be
# stopped, so the timed-out handler runs on to its end in its thread (its later output stays in its
# own invocation's capture); the process is never exited for a timeout: the instance may be serving
# other invocations, and a restart would put the pod into CrashLoopBackOff. One C call that holds the
# GIL throughout (a single huge regex match, say) holds every thread, the answering one too, until it
# returns. Knative's own revision timeout is set longer (the function's timeout plus a start-up
# allowance) and is only a backstop. Worker threads are reused, so state a handler keeps per thread
# lasts across invocations as it does on Lambda's single-threaded runtime.
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
import base64
import importlib
import json
import os
import queue
import re
import sys
import threading
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


def _timeout_s():
    """The function's Timeout (OPENINFRA_TIMEOUT_S): whole seconds, 1-900, else 300."""
    raw = os.environ.get("OPENINFRA_TIMEOUT_S", "").strip()
    try:
        n = int(raw) if re.match(r"^[0-9]+$", raw) else 0
    except ValueError:  # more digits than int() takes
        n = 0
    if 1 <= n <= 900:
        return n
    if raw:
        sys.stderr.write(f"open-infra-runtime: OPENINFRA_TIMEOUT_S {raw!r} is not a whole number of seconds from 1 "
                         f"to 900; the timeout is 300 seconds\n")
    return 300


_TIMEOUT_S = _timeout_s()


# This instance's log stream, named as Lambda names one (<date>/[$LATEST]<id>).
_LOG_STREAM = time.strftime("%Y/%m/%d", time.gmtime()) + "/[$LATEST]" + uuid.uuid4().hex


_FUNCTION_NAME = os.environ.get("OPENINFRA_FUNCTION_NAME", "function")
_VERSION_RE = re.compile(r"^(\$LATEST|[1-9][0-9]{0,8})$")
_ROLE_ACCOUNT_RE = re.compile(r"^arn:aws[a-z-]*:iam::(\d{12}):role/")
_OWN_ARN_RE = re.compile(
    r"^arn:aws[a-z-]*:lambda:[a-z0-9-]+:\d{12}:function:" + re.escape(_FUNCTION_NAME) + r"(:[A-Za-z0-9$_-]{1,128})?$"
)


def _invoked_arn(headers):
    """The ARN the function was invoked by, as Lambda's context reports it: the one its caller passes
    (X-Openinfra-Invoked-Function-Arn), taken only when it names this function; else the function's own
    ARN, from its region and the account its role is in; "" when neither is known."""
    given = headers.get("X-Openinfra-Invoked-Function-Arn") or ""
    if _OWN_ARN_RE.match(given):
        return given
    acct = _ROLE_ACCOUNT_RE.match(os.environ.get("AWS_ROLE_ARN", ""))
    region = os.environ.get("AWS_REGION", "")
    return "arn:aws:lambda:%s:%s:function:%s" % (region, acct.group(1), _FUNCTION_NAME) if acct and region else ""


class Client:
    """The mobile client in a ClientContext, as Lambda's Python runtime gives it."""

    def __init__(self, d):
        self.installation_id = d.get("installation_id")
        self.app_title = d.get("app_title")
        self.app_version_name = d.get("app_version_name")
        self.app_version_code = d.get("app_version_code")
        self.app_package_name = d.get("app_package_name")


class ClientContext:
    """The ClientContext a caller passed to Invoke, as Lambda's Python runtime gives it."""

    def __init__(self, d):
        client = d.get("client")
        self.client = Client(client) if isinstance(client, dict) else None
        self.custom = d.get("custom")
        self.env = d.get("env")


def _client_context(headers):
    raw = headers.get("X-Amz-Client-Context")
    if not raw:
        return None
    try:
        d = json.loads(base64.b64decode(raw))
    except Exception:
        return None
    return ClientContext(d) if isinstance(d, dict) else None


_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class LambdaContext:
    """A minimal AWS Lambda context object (the fields handlers actually read). deadline is when the
    invocation's Timeout ends, on time.monotonic()'s clock."""

    def __init__(self, headers=None, deadline=None):
        headers = headers or {}
        version = headers.get("X-Openinfra-Function-Version") or ""
        request_id = headers.get("X-Openinfra-Request-Id") or ""
        # The invoke's own request ID (the aws-shim's x-amzn-RequestId), as on Lambda; else a fresh one.
        self.aws_request_id = request_id if _UUID_RE.match(request_id) else str(uuid.uuid4())
        self.function_name = _FUNCTION_NAME
        self.function_version = version if _VERSION_RE.match(version) else "$LATEST"
        self.memory_limit_in_mb = int(os.environ.get("OPENINFRA_MEMORY_MB", "0")) or 128
        self.invoked_function_arn = _invoked_arn(headers)
        self.client_context = _client_context(headers)
        self.identity = None
        self.log_group_name = "/aws/lambda/" + self.function_name
        self.log_stream_name = _LOG_STREAM
        # The deadline the bootstrap enforces (see Handler._handle).
        self._deadline = deadline if deadline is not None else time.monotonic() + _TIMEOUT_S

    def get_remaining_time_in_millis(self):
        return max(0, int((self._deadline - time.monotonic()) * 1000))


# --- The invocation's log tail (#407): Invoke with LogType Tail answers the last 4 KB of what that
# invocation printed, between Lambda's START, END and REPORT lines, in X-Amz-Log-Result. Whatever the
# invocation's thread writes to sys.stdout or sys.stderr is kept for it, so concurrent invocations never
# share output; everything still reaches the process's own streams. The invocation's thread is its worker
# (see _Worker) while the handler runs, and the request's thread while it answers a timeout.
_TAIL_BYTES = 4096
_capture = threading.local()


class _Tee:
    """A stream that also keeps what the current thread's invocation writes, when it asked for its tail."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, data):
        cap = getattr(_capture, "log", None)
        if cap is not None:
            cap.add(data)
        return self._stream.write(data)

    def flush(self):
        return self._stream.flush()

    def __getattr__(self, name):
        return getattr(self._stream, name)


class _LogCapture:
    def __init__(self):
        self.parts = []
        self.size = 0
        self.start = time.time()
        self.lock = threading.Lock()  # a timed-out handler's thread may still be writing as the tail is taken

    def add(self, data):
        b = data if isinstance(data, bytes) else str(data).encode("utf-8", "replace")
        with self.lock:
            self.parts.append(b)
            self.size += len(b)
            while len(self.parts) > 1 and self.size - len(self.parts[0]) >= _TAIL_BYTES:
                self.size -= len(self.parts.pop(0))

    def tail(self, context, status=None):
        """X-Amz-Log-Result: base64 of the last 4 KB of START, the output, END and REPORT (with Lambda's
        "Status: <status>" when the invocation did not succeed or fail on its own: "timeout")."""
        ms = (time.time() - self.start) * 1000
        with self.lock:
            out = b"".join(self.parts).decode("utf-8", "replace")
        if out and not out.endswith("\n"):
            out += "\n"
        rid = context.aws_request_id
        try:
            import resource

            used = (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss + 1023) // 1024  # KiB on Linux
        except Exception:
            used = 0
        log = (
            "START RequestId: %s Version: %s\n%sEND RequestId: %s\n"
            "REPORT RequestId: %s\tDuration: %.2f ms\tBilled Duration: %d ms\tMemory Size: %d MB\tMax Memory Used: %d MB\t%s\n"
            % (rid, context.function_version, out, rid, rid, ms, -(-ms // 1), context.memory_limit_in_mb, used,
               "Status: " + status if status else "")
        ).encode("utf-8")
        return base64.b64encode(log[-_TAIL_BYTES:]).decode("ascii")


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


class _Worker:
    """A thread that runs handlers, one invocation at a time, so the request's thread is free to answer
    the invocation at its deadline. An idle worker is reused (the most recently idle first), so what a
    handler keeps per thread lasts across invocations; one idle for _WORKER_IDLE_S ends. A worker whose
    invocation timed out is busy until its handler returns, and is not given another until then."""

    _idle = []
    _lock = threading.Lock()

    def __init__(self):
        self._jobs = queue.Queue()
        threading.Thread(target=self._loop, name="open-infra-invoke", daemon=True).start()

    @classmethod
    def run(cls, job):
        """Run job (which never raises) on an idle worker, or a new one."""
        with cls._lock:
            w = cls._idle.pop() if cls._idle else None
        if w is None:
            w = cls()
        w._jobs.put(job)

    def _loop(self):
        while True:
            try:
                job = self._jobs.get(timeout=_WORKER_IDLE_S)
            except queue.Empty:
                with _Worker._lock:
                    if self in _Worker._idle:
                        _Worker._idle.remove(self)
                        return
                continue  # taken as it timed out: its job is on the way
            try:
                job()
            except Exception:
                pass  # the job reports through its own state; the worker lives on
            with _Worker._lock:
                _Worker._idle.append(self)


_WORKER_IDLE_S = 300


class _Invocation:
    """One invocation's handler call, run on a worker: what it settled with, and when."""

    def __init__(self, event, context, cap, deadline):
        self.event, self.context, self.cap, self.deadline = event, context, cap, deadline
        self.done = threading.Event()
        self.settled = None  # time.monotonic() when the handler returned or raised
        self.result = None
        self.error = None  # the Exception the handler raised
        self.fatal = None  # a BaseException that is not an Exception (SystemExit): re-raised as before

    def __call__(self):
        _capture.log = self.cap
        try:
            self.result = HANDLER(self.event, self.context)
            self.settled = time.monotonic()
        except Exception as e:
            self.settled = time.monotonic()
            self.error = e
            if self.settled < self.deadline:  # a late error is discarded, unlogged, like a late result
                sys.stderr.write("open-infra-runtime: handler raised:\n")
                traceback.print_exc()
        except BaseException as e:
            self.settled = time.monotonic()
            self.fatal = e
        finally:
            _capture.log = None
            self.done.set()

    def wait(self):
        """Wait until the handler settles or the deadline passes; True when it settled before the deadline."""
        while not self.done.is_set():
            left = self.deadline - time.monotonic()
            if left <= 0:
                break
            self.done.wait(left)
        return self.done.is_set() and self.settled < self.deadline


def _utc_timestamp():
    """Now as Lambda stamps a log line: ISO 8601 UTC with milliseconds, e.g. 2026-01-02T03:04:05.678Z."""
    now = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + ".%03dZ" % int(now % 1 * 1000)


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

    def _timed_out(self, context, cap):
        """Answer an invocation its handler did not finish by its deadline, as Lambda ends one: the line
        "Task timed out" to stdout (in the invocation's own capture), and 504 Sandbox.Timedout with no
        X-Amz-Function-Error, which the aws-shim answers as Lambda's timeout error."""
        msg = "Task timed out after %.2f seconds" % _TIMEOUT_S
        _capture.log = cap
        try:
            sys.stdout.write("%s %s %s\n" % (_utc_timestamp(), context.aws_request_id, msg))
            sys.stdout.flush()
        finally:
            _capture.log = None
        body = json.dumps({"errorType": "Sandbox.Timedout", "errorMessage": "RequestId: %s Error: %s" % (context.aws_request_id, msg)},
                          separators=(",", ":")).encode()
        self._send(504, body, extra_headers={"X-Amz-Log-Result": cap.tail(context, "timeout")} if cap is not None else None)

    def _handle(self):
        # Health probe (never collides with a real invoke).
        if self.command == "GET" and self.path == "/_openinfra_health":
            self._send(200, b'{"ok":true}')
            return
        # The invocation's clock starts when its request reaches the bootstrap (headers read, body not yet).
        deadline = time.monotonic() + _TIMEOUT_S
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
        context = LambdaContext(self.headers, deadline)
        cap = _LogCapture() if direct and self.headers.get("X-Amz-Log-Type") == "Tail" else None
        tail = {}
        # The handler runs on a worker; this thread waits for it until the deadline, and answers the timeout
        # at the deadline whatever the handler is doing (both invocation modes alike). A handler that settles
        # later is never answered: its result or error is discarded.
        inv = _Invocation(event, context, cap, deadline)
        _Worker.run(inv)
        if not inv.wait():
            self._timed_out(context, cap)
            return
        if inv.fatal is not None:
            raise inv.fatal  # sys.exit() in a handler ends the request's thread, unanswered, as before
        if inv.error is not None:
            e = inv.error
            err = json.dumps({"errorType": type(e).__name__, "errorMessage": str(e)}).encode()
            if cap is not None:
                tail = {"X-Amz-Log-Result": cap.tail(context)}
            if direct:
                self._send(200, err, extra_headers=dict(tail, **{"X-Amz-Function-Error": "Unhandled"}))
            else:
                self._send(502, err)
            return
        result = inv.result
        if cap is not None:
            tail = {"X-Amz-Log-Result": cap.tail(context)}
        if direct:
            # The raw return value IS the payload — never an HTTP proxy mapping.
            self._send(200, json.dumps(result).encode() if result is not None else b"null", extra_headers=tail)
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
    sys.stdout, sys.stderr = _Tee(sys.stdout), _Tee(sys.stderr)
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
