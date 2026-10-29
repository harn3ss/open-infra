#!/usr/bin/env node
// open-infra Lambda runtime shim (Node.js) — the "runtime interface" half of the
// runtime-base-image + handler-shim ingestion model (kind: Function spec.code). It is the
// Node sibling of lambda-runtime/python/bootstrap.py and speaks the EXACT same contract, so
// the composition wires both identically.
//
// A user ships handler CODE (a Zip/source), not a container. open-infra runs it on THIS
// prebuilt base image: the handler is unpacked into /var/task (a ConfigMap mount, or this
// shim fetches+unzips the code bucket object at cold start), and the shim requires the
// declared handler and serves it over HTTP — turning the Lambda handler(event, context)
// model into the request-driven HTTP service Knative expects.
//
// Contract (Node builtins ONLY — the handler .zip is fetched with a built-in SigV4-signed S3/MinIO
// GET; there is no AWS SDK dependency, so this shim runs on every Node version, including the older
// escape-hatch runtimes the SDK's floating major had broken):
//   OPENINFRA_HANDLER = "<module>.<export>"  e.g. "index.handler" -> index.js exports.handler
//   OPENINFRA_TASK_DIR = handler code root (default /var/task)
//   OPENINFRA_CODE_BUCKET / OPENINFRA_CODE_KEY = the handler .zip (S3/MinIO) — optional
//   OPENINFRA_LAYERS = JSON [{bucket,key}] extracted (merged, in order) into /opt — optional
//   PORT = listen port (default 8080; Knative sets it)
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
  // Fetch+unzip the handler .zip into /var/task and any declared layers into /opt at cold start.
  // A failure crashes the pod (exit 2) rather than serving a broken handler. No-op when the handler
  // is ConfigMap-mounted and no layers are declared.
  const bucket = process.env.OPENINFRA_CODE_BUCKET;
  const layersRaw = process.env.OPENINFRA_LAYERS || "";
  if (!bucket && !layersRaw) return;
  try {
    const cfg = s3Config();
    if (bucket) await fetchUnzip(cfg, bucket, process.env.OPENINFRA_CODE_KEY || "", TASK_DIR);
    if (layersRaw) {
      for (const layer of JSON.parse(layersRaw)) {
        await fetchUnzip(cfg, layer.bucket, layer.key || "", OPT_DIR);
      }
    }
  } catch (e) {
    process.stderr.write("open-infra-runtime: failed to fetch/unzip handler or layer code:\n" + (e && e.stack ? e.stack : String(e)) + "\n");
    process.exit(2);
  }
}

function addLayerPaths() {
  // Lambda Node layers carry a `nodejs/node_modules` (and/or nodejs/node<major>/node_modules) tree
  // extracted under /opt, so a handler can require() modules the layer provides. Put them on
  // NODE_PATH and re-init the module resolver.
  const candidates = [
    path.join(OPT_DIR, "nodejs", "node_modules"),
    path.join(OPT_DIR, "nodejs", `node${process.versions.node.split(".")[0]}`, "node_modules"),
  ].filter((p) => {
    try { return fs.statSync(p).isDirectory(); } catch (_e) { return false; }
  });
  if (candidates.length) {
    process.env.NODE_PATH = [process.env.NODE_PATH, ...candidates].filter(Boolean).join(path.delimiter);
    require("module").Module._initPaths();
  }
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

function lambdaContext() {
  const deadline = Date.now() + parseInt(process.env.OPENINFRA_TIMEOUT_S || "300", 10) * 1000;
  return {
    awsRequestId: randomUUID(),
    functionName: process.env.OPENINFRA_FUNCTION_NAME || "function",
    functionVersion: "$LATEST",
    memoryLimitInMB: String(parseInt(process.env.OPENINFRA_MEMORY_MB || "0", 10) || 128),
    invokedFunctionArn: "",
    getRemainingTimeInMillis: () => Math.max(0, deadline - Date.now()),
  };
}

// invoke calls the handler supporting BOTH async (Promise-returning) and callback styles, exactly as
// AWS does: whichever settles first wins.
function invoke(fn, event, context) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (err, res) => {
      if (settled) return;
      settled = true;
      err ? reject(err) : resolve(res);
    };
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
    const handler = await loadHandler();
    process.stderr.write(
      `open-infra-runtime: serving ${process.env.OPENINFRA_HANDLER} on :${PORT} ` +
        `(task dir ${TASK_DIR}, cold-start ${((Date.now() - START) / 1000).toFixed(3)}s)\n`
    );

    const server = http.createServer((req, res) => {
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
          if (event === null || typeof event !== "object" || Array.isArray(event)) event = { body: event };
        } catch (_e) {
          event = { body: raw };
        }
        if (!direct) {
          const q = req.url.split("?");
          event._http = { method: req.method, path: q[0], query: q[1] || "", headers: req.headers };
        }
        let result;
        try {
          result = await invoke(handler, event, lambdaContext());
        } catch (e) {
          process.stderr.write("open-infra-runtime: handler raised:\n" + (e && e.stack ? e.stack : String(e)) + "\n");
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
