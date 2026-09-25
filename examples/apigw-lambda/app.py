"""A minimal API Gateway (HTTP API v2) → Lambda handler for open-infra.

This is what a real AWS Lambda behind an API Gateway HTTP API looks like: it receives the API Gateway v2
*proxy event* as its request body and returns a *structured proxy response* — {statusCode, headers, body,
isBase64Encoded} — which the gateway turns back into a real HTTP response. Written against the same contract
AWS documents, so a handler proven here is a handler that runs on AWS unchanged.

It echoes the event it received back in the response body (so a caller can see exactly what the gateway
built) and deliberately returns statusCode 201 with a custom header, so the caller can confirm the
gateway honored the function's chosen status and headers rather than defaulting to 200.
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8080


class Handler(BaseHTTPRequestHandler):
    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            event = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            event = {"_unparsed": raw.decode("utf-8", "replace")}

        # A structured API Gateway v2 proxy response. statusCode 201 + a custom header prove that the
        # gateway propagates the function's chosen status and headers into the real HTTP response.
        response = {
            "statusCode": 201,
            "headers": {"content-type": "application/json", "x-lambda": "apigw-echo"},
            "body": json.dumps({"received": event}),
            "isBase64Encoded": False,
        }
        payload = json.dumps(response).encode("utf-8")
        self.send_response(200)  # the FUNCTION's HTTP layer always returns 200; the proxy shape is in the body
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        self._handle()

    def do_GET(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def log_message(self, *args):  # keep the container logs quiet
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
