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
// Contract (Node builtins only at module scope — the AWS SDK is required lazily, so the
// inline-ConfigMap path never loads it):
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
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const TASK_DIR = process.env.OPENINFRA_TASK_DIR || "/var/task";
const OPT_DIR = process.env.OPENINFRA_OPT_DIR || "/opt";
const PORT = parseInt(process.env.PORT || "8080", 10);
const START = Date.now();

function s3Client() {
  // Lazy require so the inline-ConfigMap path never loads the SDK. Path-style addressing when a
  // custom AWS_ENDPOINT_URL (MinIO / any S3 gateway) is set; untouched on real AWS.
  const { S3Client } = require("@aws-sdk/client-s3");
  const endpoint = process.env.AWS_ENDPOINT_URL || undefined;
  return new S3Client({
    endpoint,
    forcePathStyle: Boolean(endpoint),
    region: process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || "us-east-1",
  });
}

async function fetchUnzip(client, bucket, key, dest) {
  const { GetObjectCommand } = require("@aws-sdk/client-s3");
  const out = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  const chunks = [];
  for await (const c of out.Body) chunks.push(c);
  const buf = Buffer.concat(chunks);
  fs.mkdirSync(dest, { recursive: true });
  const tmp = path.join(os.tmpdir(), `oi-${process.pid}-${chunks.length}.zip`);
  fs.writeFileSync(tmp, buf);
  // Node has no stdlib zip-archive reader; use the system `unzip` (in the base image), the same
  // way the python shim uses zipfile. -o overwrite, -q quiet.
  execFileSync("unzip", ["-o", "-q", tmp, "-d", dest]);
  fs.unlinkSync(tmp);
  process.stderr.write(`open-infra-runtime: unpacked s3://${bucket}/${key} (${buf.length} bytes) into ${dest}\n`);
}

async function fetchCode() {
  // Fetch+unzip the handler .zip into /var/task and any declared layers into /opt at cold start.
  // A failure crashes the pod (exit 2) rather than serving a broken handler. No-op when the handler
  // is ConfigMap-mounted and no layers are declared.
  const bucket = process.env.OPENINFRA_CODE_BUCKET;
  const layersRaw = process.env.OPENINFRA_LAYERS || "";
  if (!bucket && !layersRaw) return;
  try {
    const client = s3Client();
    if (bucket) await fetchUnzip(client, bucket, process.env.OPENINFRA_CODE_KEY || "", TASK_DIR);
    if (layersRaw) {
      for (const layer of JSON.parse(layersRaw)) {
        await fetchUnzip(client, layer.bucket, layer.key || "", OPT_DIR);
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
    try { return fs.statSync(p).isDirectory(); } catch { return false; }
  });
  if (candidates.length) {
    process.env.NODE_PATH = [process.env.NODE_PATH, ...candidates].filter(Boolean).join(path.delimiter);
    require("module").Module._initPaths();
  }
}

function loadHandler() {
  // Import the declared handler once at startup; a bad handler crashes the pod (non-zero exit) so the
  // failure is visible, never served as a false 200. CommonJS handlers (require-resolvable) in v1;
  // an ESM-only handler (.mjs / "type":"module") is a known limitation.
  const spec = process.env.OPENINFRA_HANDLER || "";
  const i = spec.lastIndexOf(".");
  if (i < 1) {
    process.stderr.write(`open-infra-runtime: OPENINFRA_HANDLER must be '<module>.<export>', got '${spec}'\n`);
    process.exit(2);
  }
  const modName = spec.slice(0, i);
  const fnName = spec.slice(i + 1);
  let mod;
  try {
    mod = require(path.resolve(TASK_DIR, modName));
  } catch (e) {
    process.stderr.write(`open-infra-runtime: cannot load handler '${spec}' from ${TASK_DIR}:\n` + (e && e.stack ? e.stack : String(e)) + "\n");
    process.exit(2);
  }
  const fn = mod && mod[fnName];
  if (typeof fn !== "function") {
    process.stderr.write(`open-infra-runtime: handler export '${fnName}' is not a function in '${modName}'\n`);
    process.exit(2);
  }
  return fn;
}

function lambdaContext() {
  const deadline = Date.now() + parseInt(process.env.OPENINFRA_TIMEOUT_S || "300", 10) * 1000;
  return {
    awsRequestId: require("crypto").randomUUID(),
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
    const handler = loadHandler();
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
        let event;
        try {
          event = raw.trim() ? JSON.parse(raw) : {};
          if (event === null || typeof event !== "object" || Array.isArray(event)) event = { body: event };
        } catch {
          event = { body: raw };
        }
        const q = req.url.split("?");
        event._http = { method: req.method, path: q[0], query: q[1] || "", headers: req.headers };
        let result;
        try {
          result = await invoke(handler, event, lambdaContext());
        } catch (e) {
          process.stderr.write("open-infra-runtime: handler raised:\n" + (e && e.stack ? e.stack : String(e)) + "\n");
          return send(502, JSON.stringify({ errorType: (e && e.name) || "Error", errorMessage: (e && e.message) || String(e) }));
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
