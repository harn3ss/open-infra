#!/usr/bin/env node
// open-infra Lambda runtime shim (Node.js) — the "runtime interface" half of the
// runtime-base-image + handler-shim ingestion model (kind: Function spec.code). It is the
// Node sibling of lambda-runtime/python/bootstrap.py and speaks the EXACT same contract, so
// the composition wires both identically.
//
// A user ships handler CODE (a Zip/source), not a container. open-infra runs it on THIS
// prebuilt base image: the handler is unpacked into /var/task (a ConfigMap mount, or this
// shim fetches+unzips the function's stored deployment package or the code bucket object at
// cold start), and the shim requires the
// declared handler and serves it over HTTP — turning the Lambda handler(event, context)
// model into the request-driven HTTP service Knative expects.
//
// Contract (Node builtins ONLY — the handler .zip is fetched with a built-in SigV4-signed S3/MinIO
// GET; there is no AWS SDK dependency, so this shim runs on every Node version, including the older
// escape-hatch runtimes the SDK's floating major had broken):
//   OPENINFRA_HANDLER = "<module>.<export>"  e.g. "index.handler" -> index.js exports.handler
//   OPENINFRA_TASK_DIR = handler code root (default /var/task)
//   OPENINFRA_CODE_BUCKET / OPENINFRA_CODE_KEY = the handler .zip (S3/MinIO) — optional
//   OPENINFRA_CODE_URL = the function's stored deployment package, served by the aws-shim — optional,
//     never together with OPENINFRA_CODE_BUCKET. Fetched with the function's own identity token, no keys:
//     OPENINFRA_CODE_SHA256 = the package's recorded SHA-256 (64 lowercase hex), checked before unpacking
//     OPENINFRA_CODE_TOKEN_FILE = the projected identity token, sent as "Authorization: Bearer <token>"
//   OPENINFRA_LAYERS = JSON [{bucket,key}] extracted (merged, in order) into /opt — optional. Each layer .zip
//     is fetched from S3/MinIO with the code bucket's keys, unless:
//     OPENINFRA_LAYERS_URL = the function's layers, served by the aws-shim: layer i (0-based, in the order of
//       OPENINFRA_LAYERS) is GET {OPENINFRA_LAYERS_URL}?layer={i}, fetched with the function's own identity
//       token and no keys, retried and refused as the stored deployment package is, and unpacked into /opt
//       with the same entry checks (no SHA-256: the aws-shim serves the layer version the function names).
//     OPENINFRA_LAYERS_TOKEN_FILE = the projected identity token for it, sent as "Authorization: Bearer <token>"
//   OPENINFRA_TIMEOUT_S = the function's Timeout in whole seconds, 1-900; unset, not a whole number or
//     out of range means 300. Read once at start.
//   PORT = listen port (default 8080; Knative sets it)
//
// The execution role's credentials are in the environment as Lambda hands them over: when AWS_ROLE_ARN,
// AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ENDPOINT_URL_STS are set and AWS_ACCESS_KEY_ID is not, the bootstrap
// calls sts:AssumeRoleWithWebIdentity on AWS_ENDPOINT_URL_STS at cold start (after the code and layers are
// unpacked, before the handler's module loads) and sets AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and
// AWS_SESSION_TOKEN (and AWS_CREDENTIAL_EXPIRATION, from which the AWS SDK for JavaScript v3 knows to read
// them again before they expire), so code that reads credentials as it loads finds them. Before an
// invocation, when they would expire within 5 minutes of its Timeout's end, they are refreshed the same way
// (no call otherwise). A failed call is logged in one line and never fails the function: at cold start
// nothing is set (the SDK's web identity provider still works), at a refresh the current credentials are
// kept (and the next try waits 30 seconds). The values are never logged.
//
// The function's Timeout is enforced here, as Lambda's service enforces it: each invocation's clock starts
// when its request reaches this bootstrap (a cold start, the wait for an instance, is not counted, as
// Lambda does not count init), and context.getRemainingTimeInMillis() counts down to that deadline. An
// invocation still running at its deadline is answered at once with 504, Content-Type application/json and
// no X-Amz-Function-Error (the aws-shim answers that as Lambda's timeout error), the body
// {"errorType":"Sandbox.Timedout","errorMessage":"RequestId: <id> Error: Task timed out after <T>.00 seconds"};
// the line "<UTC time> <id> Task timed out after <T>.00 seconds" goes to stdout and, for a LogType Tail
// invoke, into X-Amz-Log-Result before END and a REPORT ending "Status: timeout". The handler's result or
// error arriving later is discarded, never sent. The process is never exited for a timeout: the instance
// may be serving other invocations, and a restart would put the pod into CrashLoopBackOff. Knative's own
// revision timeout is set longer (the function's timeout plus a start-up allowance) and is only a backstop.
// The deadline is a timer on the event loop, so a handler that runs synchronously (a CPU loop, a sync
// call that blocks) holds the loop and cannot be answered while it runs: it is answered with the timeout
// the moment it gives the loop back, and its result is discarded. One that never gives it back is never
// answered, and holds every other invocation on the instance too: only Knative's revision timeout ends
// that request.
//
// Invocation model (identical to the python shim):
//   - POST with a JSON body -> that JSON is the `event`; non-JSON -> event={"body": <raw>}.
//   - The HTTP facts are always attached at event._http {method, path, query, headers}.
//   - Handler may be async (returns a Promise) OR callback-style (event, context, cb).
//   - Return a dict with "statusCode" -> used verbatim (API-Gateway proxy shape); anything
//     else -> 200 with the value JSON-encoded. An unhandled throw/reject -> 502
//     {errorType, errorMessage} + stderr log, never a silent 200.
//   - GET /_openinfra_health -> 200 (never collides with a real invoke).
"use strict";

const http = require("http");
const https = require("https");
const crypto = require("crypto");
const url = require("url");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const TASK_DIR = process.env.OPENINFRA_TASK_DIR || "/var/task";
const OPT_DIR = process.env.OPENINFRA_OPT_DIR || "/opt";
const PORT = parseInt(process.env.PORT || "8080", 10);
const START = Date.now();

// TIMEOUT_S is the function's Timeout (OPENINFRA_TIMEOUT_S): whole seconds, 1-900, else 300.
const TIMEOUT_S = (function () {
  const raw = String(process.env.OPENINFRA_TIMEOUT_S || "").trim();
  const n = /^[0-9]+$/.test(raw) ? Number(raw) : NaN;
  if (n >= 1 && n <= 900) return n;
  if (raw) process.stderr.write(`open-infra-runtime: OPENINFRA_TIMEOUT_S '${raw}' is not a whole number of seconds from 1 to 900; the timeout is 300 seconds\n`);
  return 300;
})();

// monoMs is a monotonic clock in milliseconds (process.hrtime: every Node version), for invocation deadlines.
function monoMs() {
  const t = process.hrtime();
  return t[0] * 1e3 + t[1] / 1e6;
}

// --- Code fetch: a built-in SigV4-signed S3/MinIO GET. No AWS SDK, so cold-start code fetch works on
// every Node version (the SDK's floating `@aws-sdk/client-s3@3` required Node >= 18 and broke the older
// escape-hatch runtimes). Uses only crypto + http(s). Same env contract as before:
//   AWS_ENDPOINT_URL (MinIO / S3 gateway; path-style), AWS_REGION, AWS_ACCESS_KEY_ID,
//   AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN (optional).
function s3Config() {
  const region = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || "us-east-1";
  // Path-style against a custom endpoint (MinIO / any S3 gateway); fall back to AWS S3 for that region.
  // Service-scoped AWS_ENDPOINT_URL_S3 first (so a handler's global endpoint isn't forced to the S3
  // gateway); fall back to the legacy global AWS_ENDPOINT_URL, then to real AWS S3 for the region.
  const endpoint = process.env.AWS_ENDPOINT_URL_S3 || process.env.AWS_ENDPOINT_URL || ("https://s3." + region + ".amazonaws.com");
  return {
    endpoint: endpoint,
    region: region,
    accessKey: process.env.AWS_ACCESS_KEY_ID || "",
    secretKey: process.env.AWS_SECRET_ACCESS_KEY || "",
    sessionToken: process.env.AWS_SESSION_TOKEN || "",
  };
}

function sha256hex(data) { return crypto.createHash("sha256").update(data).digest("hex"); }
function hmac(key, data) { return crypto.createHmac("sha256", key).update(data, "utf8").digest(); }

// Percent-encode each path segment for the SigV4 canonical URI, keeping "/" separators.
function encodeS3Path(key) {
  return key.split("/").map(function (seg) {
    return encodeURIComponent(seg).replace(/[!'()*]/g, function (c) {
      return "%" + c.charCodeAt(0).toString(16).toUpperCase();
    });
  }).join("/");
}

// Build an AWS SigV4 ("AWS4-HMAC-SHA256") GET for a path-style S3/MinIO object. Empty-body GET, so the
// payload hash is SHA-256("").  Returns http(s).request options.
function signedGet(cfg, bucket, key) {
  const ep = url.parse(cfg.endpoint);
  const host = ep.host; // host[:port]
  const canonicalUri = "/" + bucket + "/" + encodeS3Path(key);
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, ""); // YYYYMMDDTHHMMSSZ
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256hex("");
  let canonicalHeaders = "host:" + host + "\n" +
    "x-amz-content-sha256:" + payloadHash + "\n" +
    "x-amz-date:" + amzDate + "\n";
  let signedHeaders = "host;x-amz-content-sha256;x-amz-date";
  if (cfg.sessionToken) {
    canonicalHeaders += "x-amz-security-token:" + cfg.sessionToken + "\n";
    signedHeaders += ";x-amz-security-token";
  }
  const canonicalRequest = "GET\n" + canonicalUri + "\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash;
  const credScope = dateStamp + "/" + cfg.region + "/s3/aws4_request";
  const stringToSign = "AWS4-HMAC-SHA256\n" + amzDate + "\n" + credScope + "\n" + sha256hex(canonicalRequest);
  const kSigning = hmac(hmac(hmac(hmac("AWS4" + cfg.secretKey, dateStamp), cfg.region), "s3"), "aws4_request");
  const signature = crypto.createHmac("sha256", kSigning).update(stringToSign, "utf8").digest("hex");
  const headers = {
    "Host": host,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payloadHash,
    "Authorization": "AWS4-HMAC-SHA256 Credential=" + cfg.accessKey + "/" + credScope +
      ", SignedHeaders=" + signedHeaders + ", Signature=" + signature,
  };
  if (cfg.sessionToken) headers["x-amz-security-token"] = cfg.sessionToken;
  return { protocol: ep.protocol, host: ep.hostname, port: ep.port, path: canonicalUri, headers: headers };
}

// Stream a signed GET straight to a file (no whole-object buffering). Rejects on any non-200.
function httpGetToFile(signed, destFile) {
  return new Promise(function (resolve, reject) {
    const mod = signed.protocol === "https:" ? https : http;
    const req = mod.request({ host: signed.host, port: signed.port, path: signed.path, method: "GET", headers: signed.headers }, function (res) {
      if (res.statusCode !== 200) {
        const errChunks = [];
        res.on("data", function (c) { errChunks.push(c); });
        res.on("end", function () { reject(new Error("GET " + signed.path + " -> HTTP " + res.statusCode + ": " + Buffer.concat(errChunks).toString("utf8").slice(0, 400))); });
        return;
      }
      const out = fs.createWriteStream(destFile);
      res.pipe(out);
      out.on("finish", function () { out.close(function () { resolve(); }); });
      out.on("error", reject);
    });
    req.on("error", reject);
    req.end();
  });
}

// Recursive mkdir that works on EVERY Node version. fs.mkdirSync's `recursive` option is Node 10.12+;
// on older Node it is silently ignored AND the call throws when the dir already exists — and /var/task
// (and /opt) always exist, so `recursive: true` broke the fetch path on nodejs8. A guard + per-level
// create is safe everywhere and also actually creates nested paths on old Node (which the flag does not).
function mkdirp(dir) {
  if (fs.existsSync(dir)) return;
  mkdirp(path.dirname(dir));
  try { fs.mkdirSync(dir); } catch (e) { if (e.code !== "EEXIST") throw e; }
}

async function fetchUnzip(cfg, bucket, key, dest) {
  const signed = signedGet(cfg, bucket, key);
  mkdirp(dest);
  const tmp = path.join(os.tmpdir(), `oi-${process.pid}-${Date.now()}.zip`);
  await httpGetToFile(signed, tmp);
  const size = fs.statSync(tmp).size;
  // Node has no stdlib zip-archive reader; use the system `unzip` (in the base image), the same
  // way the python shim uses zipfile. -o overwrite, -q quiet.
  execFileSync("unzip", ["-o", "-q", tmp, "-d", dest]);
  fs.unlinkSync(tmp);
  process.stderr.write(`open-infra-runtime: unpacked s3://${bucket}/${key} (${size} bytes) into ${dest}\n`);
}

// --- Stored deployment package (OPENINFRA_CODE_URL): Lambda's own model, where the platform keeps the
// function's .zip and the function fetches it with its OWN identity — no keys in the pod. The aws-shim
// serves a pod only its own function's package; the shim may be restarting, so a network error, a 5xx or
// a 429 is retried (5 attempts, 1s/2s/4s/8s apart), while a refusal (400/401/403/404, any other status)
// fails start at once. The token is re-read on every attempt (kubelet rotates it) and never logged. The
// function's layers (OPENINFRA_LAYERS_URL) are fetched the same way.
const CODE_MAX_BYTES = 64 * 1024 * 1024; // a deployment package or a layer .zip
const CODE_ATTEMPTS = 5;
const CODE_IDLE_MS = 30000; // an attempt with no bytes for this long is a network error (retried)
// What a fetch is: `what` in its errors, `name` in its retry lines.
const PACKAGE = { what: "the deployment package", name: "the deployment package" };

// A start failure whose message says it all: logged alone, without a stack.
function codeError(msg) { const e = new Error(msg); e.openinfraCode = true; return e; }
function retryable(msg) { const e = new Error(msg); e.retryable = true; return e; }

// readToken reads the function's identity token from tokenFile, the file the env var tokenVar names.
function readToken(tokenFile, tokenVar) {
  tokenVar = tokenVar || "OPENINFRA_CODE_TOKEN_FILE";
  let token;
  try {
    token = fs.readFileSync(tokenFile, "utf8").trim();
  } catch (e) {
    throw codeError(`cannot read ${tokenVar}: ${e.message}`);
  }
  if (!token) throw codeError(`${tokenVar} ${tokenFile} is empty: the function's identity token is missing`);
  return token;
}

// httpTarget parses the URL the env var urlVar holds: http or https, with a host, else start fails.
function httpTarget(raw, urlVar) {
  const target = url.parse(raw);
  if ((target.protocol !== "http:" && target.protocol !== "https:") || !target.hostname) {
    throw codeError(`${urlVar} must be an http or https URL, got '${raw}'`);
  }
  return target;
}

// One GET of a .zip (item: the deployment package or a layer), streamed into destFile while it is hashed
// and held to the size cap. Resolves {size, sha256}; rejects retryable() for a network failure, a 5xx or a
// 429, codeError() otherwise.
function getPackageOnce(target, token, destFile, item) {
  item = item || PACKAGE;
  const capText = `${CODE_MAX_BYTES} byte (64 MiB) limit`;
  return new Promise(function (resolve, reject) {
    const mod = target.protocol === "https:" ? https : http;
    let settled = false;
    const fail = function (e) { if (!settled) { settled = true; reject(e); } };
    const req = mod.request({ host: target.hostname, port: target.port, path: target.path, method: "GET",
      headers: { "Authorization": "Bearer " + token } }, function (res) {
      res.on("error", function (e) { fail(retryable(`the download broke off: ${e.message}`)); });
      res.on("aborted", function () { fail(retryable("the download broke off")); });
      if (res.statusCode !== 200) {
        const errChunks = [];
        let errLen = 0;
        res.on("data", function (c) { if (errLen < 4096) { errChunks.push(c); errLen += c.length; } });
        res.on("end", function () {
          const body = Buffer.concat(errChunks).toString("utf8").slice(0, 200);
          const msg = `GET ${target.href} -> HTTP ${res.statusCode}` + (body ? ": " + body : "");
          fail(res.statusCode >= 500 || res.statusCode === 429 ? retryable(msg) : codeError(msg));
        });
        return;
      }
      const declared = res.headers["content-length"] !== undefined ? parseInt(res.headers["content-length"], 10) : -1;
      if (declared > CODE_MAX_BYTES) {
        fail(codeError(`${item.what} is ${declared} bytes, over the ${capText}`));
        req.destroy();
        return;
      }
      const hash = crypto.createHash("sha256");
      const out = fs.createWriteStream(destFile);
      let size = 0;
      out.on("error", function (e) { fail(e); req.destroy(); });
      res.on("data", function (c) {
        if (settled) return;
        size += c.length;
        if (size > CODE_MAX_BYTES) {
          fail(codeError(`${item.what} is over the ${capText}`));
          out.destroy();
          req.destroy();
          return;
        }
        hash.update(c);
        if (!out.write(c)) { res.pause(); out.once("drain", function () { res.resume(); }); }
      });
      res.on("end", function () {
        if (settled) return;
        if (!res.complete || (declared >= 0 && size !== declared)) {
          out.destroy();
          return fail(retryable(`the download broke off after ${size} bytes`));
        }
        out.on("finish", function () { out.close(function () {
          if (!settled) { settled = true; resolve({ size: size, sha256: hash.digest("hex") }); }
        }); });
        out.end();
      });
    });
    req.setTimeout(CODE_IDLE_MS, function () {
      fail(retryable(`no data from ${target.host} for ${CODE_IDLE_MS / 1000}s`));
      req.destroy();
    });
    req.on("error", function (e) { fail(retryable(e.message || String(e))); });
    req.end();
  });
}

// Entry names the package would unpack outside the task dir: absolute, or with a ".." segment. The
// system unzip would rewrite such a name and carry on; the package is refused instead.
function unsafeEntries(zipFile) {
  const names = execFileSync("unzip", ["-Z1", zipFile], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return names.split("\n").filter(function (n) {
    if (!n) return false;
    return n[0] === "/" || n[0] === "\\" || n.split(/[\\/]/).indexOf("..") !== -1;
  });
}

function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

// fetchWithIdentity GETs one .zip from the aws-shim (shown: its URL) into tmp with the function's identity
// token, read afresh from tokenFile for every attempt: a network error, a 5xx or a 429 is retried
// (CODE_ATTEMPTS attempts, 1s/2s/4s/8s apart), any other refusal fails at once. Resolves {size, sha256}.
async function fetchWithIdentity(target, shown, tokenFile, tokenVar, tmp, item) {
  for (let attempt = 1; ; attempt++) {
    try {
      return await getPackageOnce(target, readToken(tokenFile, tokenVar), tmp, item);
    } catch (e) {
      if (!e.retryable) throw e;
      if (attempt >= CODE_ATTEMPTS) {
        throw codeError(`could not fetch ${item.what} from ${shown} in ${CODE_ATTEMPTS} attempts: ${e.message}`);
      }
      const delay = Math.pow(2, attempt - 1); // 1s, 2s, 4s, 8s
      process.stderr.write(`open-infra-runtime: fetching ${item.name}: ${e.message}; retrying in ${delay}s (attempt ${attempt} of ${CODE_ATTEMPTS})\n`);
      await sleep(delay * 1000);
    }
  }
}

async function fetchPackage(codeUrl, dest) {
  const target = httpTarget(codeUrl, "OPENINFRA_CODE_URL");
  const want = process.env.OPENINFRA_CODE_SHA256 || "";
  if (!/^[0-9a-f]{64}$/.test(want)) {
    throw codeError("OPENINFRA_CODE_URL needs OPENINFRA_CODE_SHA256, the deployment package's recorded SHA-256 as 64 lowercase hex characters" +
      (want ? `; got '${want}'` : "; it is not set"));
  }
  const tokenFile = process.env.OPENINFRA_CODE_TOKEN_FILE || "";
  if (!tokenFile) throw codeError("OPENINFRA_CODE_URL needs OPENINFRA_CODE_TOKEN_FILE, the path of the function's identity token; it is not set");
  readToken(tokenFile); // unreadable or empty fails start before any request
  mkdirp(dest);
  const tmp = path.join(os.tmpdir(), `oi-${process.pid}-${Date.now()}.zip`);
  try {
    const got = await fetchWithIdentity(target, codeUrl, tokenFile, "OPENINFRA_CODE_TOKEN_FILE", tmp, PACKAGE);
    if (got.sha256 !== want) {
      throw codeError(`the deployment package does not match its recorded SHA-256 (recorded ${want.slice(0, 12)}, fetched ${got.sha256.slice(0, 12)})`);
    }
    const unsafe = unsafeEntries(tmp);
    if (unsafe.length) {
      throw codeError(`the deployment package has entries that would unpack outside ${dest}, refused: ${unsafe.slice(0, 5).join(", ")}`);
    }
    execFileSync("unzip", ["-o", "-q", tmp, "-d", dest]);
    process.stderr.write(`open-infra-runtime: unpacked the deployment package (${want.slice(0, 12)}, ${got.size} bytes) into ${dest}\n`);
  } finally {
    try { fs.unlinkSync(tmp); } catch (_e) { /* never written */ }
  }
}

// fetchLayers fetches the function's layers from the aws-shim (OPENINFRA_LAYERS_URL) with its identity
// token, never with keys, and unpacks them in order (each over the last) into dest, as the stored
// deployment package is fetched and unpacked. layers is OPENINFRA_LAYERS: layer i is ?layer=i.
async function fetchLayers(layersUrl, layers, dest) {
  httpTarget(layersUrl, "OPENINFRA_LAYERS_URL");
  if (!Array.isArray(layers)) throw codeError("OPENINFRA_LAYERS must be a JSON array of the function's layers");
  const tokenVar = "OPENINFRA_LAYERS_TOKEN_FILE";
  const tokenFile = process.env.OPENINFRA_LAYERS_TOKEN_FILE || "";
  if (!tokenFile) throw codeError("OPENINFRA_LAYERS_URL needs OPENINFRA_LAYERS_TOKEN_FILE, the path of the function's identity token; it is not set");
  readToken(tokenFile, tokenVar); // unreadable or empty fails start before any request
  mkdirp(dest);
  for (let i = 0; i < layers.length; i++) {
    const shown = layersUrl + (layersUrl.indexOf("?") === -1 ? "?" : "&") + "layer=" + i;
    const tmp = path.join(os.tmpdir(), `oi-${process.pid}-${Date.now()}-layer${i}.zip`);
    try {
      const got = await fetchWithIdentity(url.parse(shown), shown, tokenFile, tokenVar, tmp, { what: "the layer", name: `layer ${i}` });
      const unsafe = unsafeEntries(tmp);
      if (unsafe.length) {
        throw codeError(`the layer has entries that would unpack outside ${dest}, refused: ${unsafe.slice(0, 5).join(", ")}`);
      }
      execFileSync("unzip", ["-o", "-q", tmp, "-d", dest]);
      process.stderr.write(`open-infra-runtime: unpacked layer ${i} (${got.size} bytes) into ${dest}\n`);
    } catch (e) {
      throw codeError(`cannot load layer ${i} into ${dest}: ${(e && e.message) || String(e)}`);
    } finally {
      try { fs.unlinkSync(tmp); } catch (_e) { /* never written */ }
    }
  }
}

// randomUUID with a fallback for Node < 14.17 (the older escape-hatch runtimes lack crypto.randomUUID).
function randomUUID() {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const b = crypto.randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // variant
  const h = b.toString("hex");
  return h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) + "-" + h.slice(16, 20) + "-" + h.slice(20);
}

async function fetchCode() {
  // Fetch+unzip the handler .zip (the stored deployment package, or the code bucket object) into
  // /var/task and any declared layers into /opt at cold start. A failure crashes the pod (exit 2) rather
  // than serving a broken handler. No-op when the handler is ConfigMap-mounted and no layers are declared.
  const bucket = process.env.OPENINFRA_CODE_BUCKET;
  const codeUrl = process.env.OPENINFRA_CODE_URL;
  const layersRaw = process.env.OPENINFRA_LAYERS || "";
  const layersUrl = process.env.OPENINFRA_LAYERS_URL || "";
  if (!bucket && !codeUrl && !layersRaw) return;
  try {
    if (codeUrl && bucket) {
      throw codeError("OPENINFRA_CODE_URL and OPENINFRA_CODE_BUCKET are both set: a function's deployment package " +
        "comes from one code source (its stored package or an S3 object), not both");
    }
    if (codeUrl) await fetchPackage(codeUrl, TASK_DIR);
    const cfg = s3Config();
    if (bucket) await fetchUnzip(cfg, bucket, process.env.OPENINFRA_CODE_KEY || "", TASK_DIR);
    if (layersRaw && layersUrl) {
      let layers;
      try { layers = JSON.parse(layersRaw); } catch (_e) { layers = null; }
      await fetchLayers(layersUrl, layers, OPT_DIR); // with the function's identity: never the bucket's keys
    } else if (layersRaw) {
      for (const layer of JSON.parse(layersRaw)) {
        await fetchUnzip(cfg, layer.bucket, layer.key || "", OPT_DIR);
      }
    }
  } catch (e) {
    if (e && e.openinfraCode) {
      process.stderr.write("open-infra-runtime: " + e.message + "\n");
      process.exit(2);
    }
    process.stderr.write("open-infra-runtime: failed to fetch/unzip handler or layer code:\n" + (e && e.stack ? e.stack : String(e)) + "\n");
    process.exit(2);
  }
}

function addLayerPaths() {
  // Lambda Node layers carry a `nodejs/node_modules` (and/or nodejs/node<major>/node_modules) tree
  // extracted under /opt, so a handler can require() modules the layer provides. Put them on
  // NODE_PATH and re-init the module resolver. The task directory goes on it too, as Lambda's NODE_PATH
  // ends with /var/task: require("cfn-response") finds the cfn-response.js beside inline code.
  const candidates = [
    path.join(OPT_DIR, "nodejs", "node_modules"),
    path.join(OPT_DIR, "nodejs", `node${process.versions.node.split(".")[0]}`, "node_modules"),
    TASK_DIR,
  ].filter((p) => {
    try { return fs.statSync(p).isDirectory(); } catch (_e) { return false; }
  });
  if (candidates.length) {
    process.env.NODE_PATH = [process.env.NODE_PATH, ...candidates].filter(Boolean).join(path.delimiter);
    require("module").Module._initPaths();
  }
}

// --- The execution role's credentials, as Lambda hands them to a function: AWS_ACCESS_KEY_ID,
// AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN are in the environment before the handler's module loads, so
// code that reads credentials as it loads (AWS SDK v2's AWS.config.credentials, a library's constructor)
// finds them. They are the role's session from sts:AssumeRoleWithWebIdentity on AWS_ENDPOINT_URL_STS, with
// the function's own identity token; AWS_CREDENTIAL_EXPIRATION carries their expiry, without which SDK v3
// would keep the first ones in a client made at load. (SDK v2 never reads them again: a client it made at load
// keeps them until they expire.) Never logged; a failure never fails the function.
const STS_TIMEOUT_MS = 5000; // one STS call, connect to answer
const STS_DURATION_S = "43200"; // asked for first; a role whose maximum is shorter gets its maximum
const CREDS_EARLY_MS = 5 * 60 * 1000; // refreshed when they would expire this soon after an invocation's deadline
const CREDS_RETRY_MS = 30 * 1000; // after a failed refresh, the next is tried no sooner than this
const ROLE_CREDS = { active: false, nextTry: 0, inFlight: null };

function xmlUnescape(s) {
  return s.replace(/&(lt|gt|amp|quot|apos|#x[0-9a-fA-F]+|#[0-9]+);/g, function (_m, e) {
    if (e[0] === "#") return String.fromCharCode(e[1] === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
    return { lt: "<", gt: ">", amp: "&", quot: "\"", apos: "'" }[e];
  });
}

// xmlText is the text of the first <tag> element in xml (any namespace prefix), unescaped; "" when absent.
function xmlText(xml, tag) {
  const m = new RegExp("<(?:[A-Za-z0-9_.-]+:)?" + tag + "(?:\\s[^>]*)?>([^<]*)</(?:[A-Za-z0-9_.-]+:)?" + tag + ">").exec(xml);
  return m ? xmlUnescape(m[1]).trim() : "";
}

// stsPost POSTs a form to the STS endpoint: resolves {status, body}, rejects on a network error or no
// answer in STS_TIMEOUT_MS.
function stsPost(endpoint, form) {
  return new Promise(function (resolve, reject) {
    const target = url.parse(endpoint.replace(/\/+$/, "") + "/");
    const mod = target.protocol === "https:" ? https : http;
    const body = Buffer.from(form, "utf8");
    let done = false;
    let timer = null;
    const finish = function (err, val) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      err ? reject(err) : resolve(val);
    };
    const req = mod.request({ host: target.hostname, port: target.port, path: target.path, method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": body.length } }, function (res) {
      const chunks = [];
      let len = 0;
      res.on("data", function (c) { if (len < 65536) { chunks.push(c); len += c.length; } });
      res.on("end", function () { finish(null, { status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }); });
      res.on("error", function (e) { finish(e); });
      res.on("aborted", function () { finish(new Error("the answer broke off")); });
    });
    timer = setTimeout(function () {
      finish(new Error(`no answer from ${target.host} in ${STS_TIMEOUT_MS / 1000}s`));
      req.destroy();
    }, STS_TIMEOUT_MS);
    req.on("error", function (e) { finish(e); });
    req.end(body);
  });
}

// assumeRole is sts:AssumeRoleWithWebIdentity for the execution role, with the function's identity token:
// resolves {accessKeyId, secretAccessKey, sessionToken, expiration, expiresMs}. A rejection's message holds
// no credential and no token.
async function assumeRole() {
  const tokenFile = process.env.AWS_WEB_IDENTITY_TOKEN_FILE;
  let token;
  try {
    token = fs.readFileSync(tokenFile, "utf8").trim();
  } catch (e) {
    throw new Error(`cannot read AWS_WEB_IDENTITY_TOKEN_FILE ${tokenFile}: ${e.code || e.message}`);
  }
  if (!token) throw new Error(`AWS_WEB_IDENTITY_TOKEN_FILE ${tokenFile} is empty`);
  const params = [
    ["Action", "AssumeRoleWithWebIdentity"], ["Version", "2011-06-15"],
    ["RoleArn", process.env.AWS_ROLE_ARN],
    ["RoleSessionName", process.env.AWS_ROLE_SESSION_NAME || process.env.AWS_LAMBDA_FUNCTION_NAME || "lambda"],
    ["WebIdentityToken", token], ["DurationSeconds", STS_DURATION_S],
  ];
  const form = function (ps) { return ps.map(function (p) { return encodeURIComponent(p[0]) + "=" + encodeURIComponent(p[1]); }).join("&"); };
  const ok = function (r) { return r.status >= 200 && r.status < 300; };
  const endpoint = process.env.AWS_ENDPOINT_URL_STS;
  let r = await stsPost(endpoint, form(params));
  if (!ok(r) && /DurationSeconds|MaxSessionDuration/.test(r.body)) {
    r = await stsPost(endpoint, form(params.slice(0, -1))); // the role's own maximum session instead
  }
  if (!ok(r)) {
    const code = xmlText(r.body, "Code");
    const msg = xmlText(r.body, "Message").split(token).join("<token>").slice(0, 200);
    throw new Error(`STS answered HTTP ${r.status}` + (code ? ` ${code}` : "") + (msg ? `: ${msg}` : ""));
  }
  const block = /<(?:[A-Za-z0-9_.-]+:)?Credentials(?:\s[^>]*)?>([\s\S]*?)<\/(?:[A-Za-z0-9_.-]+:)?Credentials>/.exec(r.body);
  const c = block ? block[1] : "";
  const got = {
    accessKeyId: xmlText(c, "AccessKeyId"), secretAccessKey: xmlText(c, "SecretAccessKey"),
    sessionToken: xmlText(c, "SessionToken"), expiration: xmlText(c, "Expiration"),
  };
  got.expiresMs = Date.parse(got.expiration);
  if (!got.accessKeyId || !got.secretAccessKey || !got.sessionToken || isNaN(got.expiresMs)) {
    throw new Error("STS's answer has no AccessKeyId, SecretAccessKey, SessionToken and Expiration");
  }
  return got;
}

// setRoleCredentials puts the credentials in the environment, and when the next refresh is due: their
// lifetime (by the wall clock, as STS states it) is counted down on the monotonic clock.
function setRoleCredentials(c) {
  process.env.AWS_ACCESS_KEY_ID = c.accessKeyId;
  process.env.AWS_SECRET_ACCESS_KEY = c.secretAccessKey;
  process.env.AWS_SESSION_TOKEN = c.sessionToken;
  process.env.AWS_CREDENTIAL_EXPIRATION = c.expiration;
  ROLE_CREDS.active = true;
  ROLE_CREDS.nextTry = monoMs() + (c.expiresMs - Date.now()) - CREDS_EARLY_MS - TIMEOUT_S * 1000;
}

// initRoleCredentials runs at cold start, before the handler's module loads.
async function initRoleCredentials() {
  const e = process.env;
  if (!e.AWS_ROLE_ARN || !e.AWS_WEB_IDENTITY_TOKEN_FILE || !e.AWS_ENDPOINT_URL_STS || e.AWS_ACCESS_KEY_ID) return;
  try {
    const c = await assumeRole();
    setRoleCredentials(c);
    process.stderr.write(`open-infra-runtime: the execution role's credentials are in the environment (expiring ${c.expiration})\n`);
  } catch (err) {
    process.stderr.write(`open-infra-runtime: the execution role's credentials are not in the environment: ${err.message}; ` +
      "the AWS SDK gets them with the web identity token instead\n");
  }
}

// refreshRoleCredentials is called before each invocation: a promise when a refresh is under way (the
// invocation waits for it), else null — no call at all until the credentials near their expiry.
function refreshRoleCredentials() {
  if (ROLE_CREDS.inFlight) return ROLE_CREDS.inFlight;
  if (!ROLE_CREDS.active || monoMs() < ROLE_CREDS.nextTry) return null;
  ROLE_CREDS.inFlight = (async function () {
    try {
      const c = await assumeRole();
      setRoleCredentials(c);
      process.stderr.write(`open-infra-runtime: refreshed the execution role's credentials (expiring ${c.expiration})\n`);
    } catch (err) {
      ROLE_CREDS.nextTry = monoMs() + CREDS_RETRY_MS;
      process.stderr.write(`open-infra-runtime: could not refresh the execution role's credentials: ${err.message}; the current ones are kept\n`);
    } finally {
      ROLE_CREDS.inFlight = null;
    }
  })();
  return ROLE_CREDS.inFlight;
}

// packageIsModule reports whether /var/task is an ESM package ("type":"module" in package.json),
// which decides how a bare .js handler loads — exactly as Node/AWS Lambda resolve it.
function packageIsModule(dir) {
  try {
    const pj = path.join(dir, "package.json");
    if (fs.existsSync(pj)) return JSON.parse(fs.readFileSync(pj, "utf8")).type === "module";
  } catch (_e) { /* unreadable/invalid package.json -> default CommonJS */ }
  return false;
}

async function loadHandler() {
  // Import the declared handler once at startup; a bad handler crashes the pod (non-zero exit) so the
  // failure is visible, never served as a false 200. Supports BOTH CommonJS and ESM handlers, the way
  // AWS Lambda's Node runtimes do: a .mjs file is ESM, a .cjs file is CommonJS, and a bare .js file is
  // ESM iff the package.json says "type":"module" (else CommonJS). ESM loads via dynamic import().
  const spec = process.env.OPENINFRA_HANDLER || "";
  const i = spec.lastIndexOf(".");
  if (i < 1) {
    process.stderr.write(`open-infra-runtime: OPENINFRA_HANDLER must be '<module>.<export>', got '${spec}'\n`);
    process.exit(2);
  }
  const modName = spec.slice(0, i);
  const fnName = spec.slice(i + 1);
  const base = path.resolve(TASK_DIR, modName);

  // Resolve the handler file + module system (mirrors Lambda's extension precedence).
  let file = null;
  let esm = false;
  if (fs.existsSync(base + ".mjs")) { file = base + ".mjs"; esm = true; }
  else if (fs.existsSync(base + ".cjs")) { file = base + ".cjs"; esm = false; }
  else if (fs.existsSync(base + ".js")) { file = base + ".js"; esm = packageIsModule(TASK_DIR); }
  // else: no direct file match — fall back to require's own resolution (subpaths, a dir's index.js,
  // node_modules). That path is CommonJS; an ESM-only module there would fail loudly below.

  let mod;
  try {
    if (file && esm) {
      // Dynamic import() via the Function constructor so this shim PARSES on Node < 12, where `import()`
      // is a syntax error. ESM handlers only exist on Node >= 12 anyway; on older Node an .mjs/ESM
      // handler throws a clear error here (caught below) instead of making the whole shim fail to load.
      const dynamicImport = new Function("u", "return import(u);");
      mod = await dynamicImport(url.pathToFileURL(file).href);
    } else {
      mod = require(file || base);
    }
  } catch (e) {
    process.stderr.write(`open-infra-runtime: cannot load handler '${spec}' from ${TASK_DIR}:\n` + (e && e.stack ? e.stack : String(e)) + "\n");
    process.exit(2);
  }

  // Resolve the named export: CJS exports.<fn>, an ESM named export, or a default-exported object's
  // property (covers `export default { handler }` and transpiled `module.exports = { handler }`).
  let fn = mod && mod[fnName];
  if (typeof fn !== "function" && mod && mod.default) {
    fn = typeof mod.default[fnName] === "function" ? mod.default[fnName]
       : (fnName === "default" && typeof mod.default === "function" ? mod.default : undefined);
  }
  if (typeof fn !== "function") {
    process.stderr.write(`open-infra-runtime: handler export '${fnName}' is not a function in '${modName}'\n`);
    process.exit(2);
  }
  return fn;
}

// LOG_STREAM is this instance's log stream, named as Lambda names one (<date>/[$LATEST]<id>).
const LOG_STREAM = new Date().toISOString().slice(0, 10).replace(/-/g, "/") + "/[$LATEST]" + randomUUID().replace(/-/g, "");

// AWS_EXECUTION_ENV is Lambda's runtime identifier, AWS_Lambda_nodejs<N>.x: the platform stores a Node runtime
// without its ".x", so it is completed here, before any handler code reads it.
if (/^AWS_Lambda_nodejs\d+$/.test(process.env.AWS_EXECUTION_ENV || "")) process.env.AWS_EXECUTION_ENV += ".x";

const FN_NAME = process.env.OPENINFRA_FUNCTION_NAME || "function";

// invokedArn is the ARN the function was invoked by, as Lambda's context reports it: the one its caller
// passes (X-Openinfra-Invoked-Function-Arn), taken only when it names this function; else the function's
// own ARN, from its region and the account its role is in; "" when neither is known.
function invokedArn(headers) {
  const given = String(headers["x-openinfra-invoked-function-arn"] || "");
  const own = new RegExp("^arn:aws[a-z-]*:lambda:[a-z0-9-]+:\\d{12}:function:" + FN_NAME.replace(/[^A-Za-z0-9-]/g, "") + "(:[A-Za-z0-9$_-]{1,128})?$");
  if (own.test(given)) return given;
  const acct = /^arn:aws[a-z-]*:iam::(\d{12}):role\//.exec(process.env.AWS_ROLE_ARN || "");
  const region = process.env.AWS_REGION || "";
  return acct && region ? `arn:aws:lambda:${region}:${acct[1]}:function:${FN_NAME}` : "";
}

// clientContext is the ClientContext the caller passed (X-Amz-Client-Context, base64 JSON), parsed, as
// Lambda's Node.js runtime gives it; undefined when none was passed.
function clientContext(headers) {
  const raw = headers["x-amz-client-context"];
  if (!raw) return undefined;
  try {
    return JSON.parse(Buffer.from(String(raw), "base64").toString("utf8"));
  } catch (_e) {
    return undefined;
  }
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// lambdaContext is the invocation's context; deadline (monoMs) is when its Timeout ends.
function lambdaContext(headers = {}, deadline = monoMs() + TIMEOUT_S * 1000) {
  const version = String(headers["x-openinfra-function-version"] || "");
  const requestId = String(headers["x-openinfra-request-id"] || "");
  return {
    // The invoke's own request ID (the aws-shim's x-amzn-RequestId), as on Lambda; else a fresh one.
    awsRequestId: UUID_RE.test(requestId) ? requestId : randomUUID(),
    functionName: FN_NAME,
    functionVersion: /^(\$LATEST|[1-9][0-9]{0,8})$/.test(version) ? version : "$LATEST",
    memoryLimitInMB: String(parseInt(process.env.OPENINFRA_MEMORY_MB || "0", 10) || 128),
    invokedFunctionArn: invokedArn(headers),
    logGroupName: "/aws/lambda/" + FN_NAME,
    logStreamName: LOG_STREAM,
    clientContext: clientContext(headers),
    identity: undefined,
    // Lambda's default. Here the response is sent when the handler's callback is called, whatever its
    // value, and work the handler leaves running continues (the process is not frozen between
    // invocations): what Lambda does with false.
    callbackWaitsForEmptyEventLoop: true,
    getRemainingTimeInMillis: () => Math.max(0, Math.floor(deadline - monoMs())),
  };
}

// --- The invocation's log tail (#407): Invoke with LogType Tail answers the last 4 KB of what that
// invocation printed, between Lambda's START, END and REPORT lines, in X-Amz-Log-Result. Whatever is written
// to stdout or stderr in the invocation's own async context is kept for it, so concurrent invocations
// never share output; everything still reaches the process's own streams. AsyncLocalStorage is Node
// 12.17+: on an older Node the tail has the START, END and REPORT lines only.
const TAIL_BYTES = 4096;
const LOG_CAPTURE = (() => {
  try {
    return new (require("async_hooks").AsyncLocalStorage)();
  } catch (_e) {
    return null;
  }
})();

class LogCapture {
  constructor() {
    this.chunks = [];
    this.size = 0;
    this.start = process.hrtime();
  }
  add(chunk, encoding) {
    const b = Buffer.isBuffer(chunk) ? chunk : typeof chunk === "string" ? Buffer.from(chunk, encoding || "utf8") : Buffer.from(chunk);
    this.chunks.push(b);
    this.size += b.length;
    while (this.chunks.length > 1 && this.size - this.chunks[0].length >= TAIL_BYTES) this.size -= this.chunks.shift().length;
  }
  // tail is X-Amz-Log-Result: base64 of the last 4 KB of START, the output, END and REPORT (with Lambda's
  // "Status: <status>" when the invocation did not succeed or fail on its own: "timeout").
  tail(context, status) {
    const d = process.hrtime(this.start);
    const ms = d[0] * 1e3 + d[1] / 1e6;
    let out = Buffer.concat(this.chunks).toString("utf8");
    if (out && !out.endsWith("\n")) out += "\n";
    const id = context.awsRequestId;
    const used = Math.ceil(process.memoryUsage().rss / 1048576);
    const log = `START RequestId: ${id} Version: ${context.functionVersion}\n${out}END RequestId: ${id}\n` +
      `REPORT RequestId: ${id}\tDuration: ${ms.toFixed(2)} ms\tBilled Duration: ${Math.ceil(ms)} ms\t` +
      `Memory Size: ${context.memoryLimitInMB} MB\tMax Memory Used: ${used} MB\t` + (status ? `Status: ${status}` : "") + "\n";
    const b = Buffer.from(log, "utf8");
    return b.slice(Math.max(0, b.length - TAIL_BYTES)).toString("base64");
  }
}

if (LOG_CAPTURE) {
  for (const stream of [process.stdout, process.stderr]) {
    const write = stream.write.bind(stream);
    stream.write = function (chunk, encoding, cb) {
      const cap = LOG_CAPTURE.getStore();
      if (cap) cap.add(chunk, typeof encoding === "string" ? encoding : "utf8");
      return write(chunk, encoding, cb);
    };
  }
}

// withLogCapture runs fn in cap's async context (when the invocation asked for its tail).
function withLogCapture(cap, fn) {
  return cap && LOG_CAPTURE ? LOG_CAPTURE.run(cap, fn) : fn();
}

// invoke calls the handler supporting async (Promise-returning) and callback styles, and the legacy
// context.done / succeed / fail (which cfn-response calls), exactly as AWS does: whichever settles first
// wins.
function invoke(fn, event, context) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (err, res) => {
      if (settled) return;
      settled = true;
      err ? reject(err) : resolve(res);
    };
    context.done = (err, res) => done(err, res);
    context.succeed = (res) => done(null, res);
    context.fail = (err) => done(err || new Error("handler failed"));
    let ret;
    try {
      ret = fn(event, context, done);
    } catch (e) {
      return done(e);
    }
    if (ret && typeof ret.then === "function") ret.then((r) => done(null, r), done);
  });
}

function main() {
  // Node runs fetch+load synchronously-before-serve via an async IIFE (mirrors python main()).
  (async () => {
    await fetchCode();
    addLayerPaths(); // layer modules require()-able before the handler loads
    await initRoleCredentials(); // the role's credentials in the environment before the handler loads
    const handler = await loadHandler();
    process.stderr.write(
      `open-infra-runtime: serving ${process.env.OPENINFRA_HANDLER} on :${PORT} ` +
        `(task dir ${TASK_DIR}, cold-start ${((Date.now() - START) / 1000).toFixed(3)}s)\n`
    );

    const server = http.createServer((req, res) => {
      const received = monoMs(); // the invocation's clock starts when its request reaches the bootstrap
      const send = (status, body, ctype = "application/json") => {
        const b = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
        res.writeHead(status, { "Content-Type": ctype, "Content-Length": b.length });
        res.end(b);
      };
      if (req.method === "GET" && req.url.split("?")[0] === "/_openinfra_health") {
        return send(200, '{"ok":true}');
      }
      const parts = [];
      req.on("data", (c) => parts.push(c));
      req.on("end", async () => {
        // The role's credentials, refreshed first when they near their expiry. The wait is the platform's,
        // not the invocation's: it is not counted against its Timeout.
        let held = 0;
        const refreshing = refreshRoleCredentials();
        if (refreshing) {
          const t = monoMs();
          await refreshing;
          held = monoMs() - t;
        }
        const raw = Buffer.concat(parts).toString("utf8");
        // Direct-invoke mode (AWS `Invoke` semantics) when the caller sets X-Openinfra-Invoke: direct —
        // the shim's Invoke, open-appsync, and Step Functions all do. Then the handler's RAW return
        // value is the response payload (a {statusCode,...} shape is DATA, never an HTTP mapping), a
        // thrown error is signalled by the X-Amz-Function-Error header with HTTP still 200, and the
        // event is passed through verbatim (no _http). Without the header, the legacy API-Gateway proxy
        // mapping below applies — for genuine API Gateway callers only.
        const direct = req.headers["x-openinfra-invoke"] === "direct";
        let event;
        try {
          event = raw.trim() ? JSON.parse(raw) : {};
          // Direct: any JSON payload is the event as sent — a list (AppSync's BatchInvoke), a string,
          // null — as Lambda Invoke passes it. Only the proxy mapping needs an object to carry _http.
          if (!direct && (event === null || typeof event !== "object" || Array.isArray(event))) event = { body: event };
        } catch (_e) {
          event = { body: raw };
        }
        if (!direct) {
          const q = req.url.split("?");
          event._http = { method: req.method, path: q[0], query: q[1] || "", headers: req.headers };
        }
        let result;
        const deadline = received + held + TIMEOUT_S * 1000;
        const context = lambdaContext(req.headers, deadline);
        const cap = direct && String(req.headers["x-amz-log-type"] || "") === "Tail" ? new LogCapture() : null;
        let raised = null;
        // The function's Timeout: at the deadline the invocation is answered as Lambda ends one, whatever the
        // handler is doing; what it settles with afterwards is discarded. Both invocation modes alike.
        let answered = false;
        const timedOut = () => {
          if (answered) return;
          answered = true;
          clearTimeout(timer);
          const msg = `Task timed out after ${TIMEOUT_S.toFixed(2)} seconds`;
          const line = `${new Date().toISOString()} ${context.awsRequestId} ${msg}\n`;
          withLogCapture(cap, () => process.stdout.write(line));
          if (cap && !LOG_CAPTURE) cap.add(line); // no async context to capture by on this Node: add it directly
          if (cap) res.setHeader("X-Amz-Log-Result", cap.tail(context, "timeout"));
          send(504, JSON.stringify({ errorType: "Sandbox.Timedout", errorMessage: `RequestId: ${context.awsRequestId} Error: ${msg}` }));
        };
        // A timer may fire a little early by the monotonic clock: it is then set again for what is left, so
        // an invocation is never answered before its deadline.
        const onTimer = () => {
          const left = deadline - monoMs();
          if (left > 0) timer = setTimeout(onTimer, Math.ceil(left));
          else timedOut();
        };
        let timer = setTimeout(onTimer, Math.ceil(Math.max(0, deadline - monoMs())));
        let settled = 0;
        await withLogCapture(cap, async () => {
          try {
            result = await invoke(handler, event, context);
            settled = monoMs();
          } catch (e) {
            settled = monoMs();
            raised = { e };
            if (!answered && settled < deadline) {
              process.stderr.write("open-infra-runtime: handler raised:\n" + (e && e.stack ? e.stack : String(e)) + "\n");
            }
          }
        });
        if (answered) return; // answered with the timeout: the late result or error is discarded
        // Settled at or past the deadline before the timer could run (a synchronous handler held the event
        // loop): Lambda would have ended it, so it is answered with the timeout, not with its late result.
        if (settled >= deadline) return timedOut();
        answered = true;
        clearTimeout(timer);
        if (cap) res.setHeader("X-Amz-Log-Result", cap.tail(context));
        if (raised) {
          const e = raised.e;
          const errBody = JSON.stringify({ errorType: (e && e.name) || "Error", errorMessage: (e && e.message) || String(e) });
          if (direct) {
            const eb = Buffer.from(errBody);
            res.writeHead(200, { "Content-Type": "application/json", "Content-Length": eb.length, "X-Amz-Function-Error": "Unhandled" });
            return res.end(eb);
          }
          return send(502, errBody);
        }
        if (direct) {
          // The raw return value IS the payload — never an HTTP proxy mapping.
          return send(200, result !== undefined ? JSON.stringify(result) : "null");
        }
        // API-Gateway proxy shape -> verbatim; else 200 + JSON.
        if (result && typeof result === "object" && "statusCode" in result) {
          let body = result.body != null ? result.body : "";
          if (typeof body !== "string" && !Buffer.isBuffer(body)) body = JSON.stringify(body);
          const ctype = (result.headers && result.headers["Content-Type"]) || "application/json";
          return send(parseInt(result.statusCode, 10) || 200, body, ctype);
        }
        return send(200, result !== undefined ? JSON.stringify(result) : "null");
      });
    });
    server.listen(PORT, "0.0.0.0");
  })();
}

main();
