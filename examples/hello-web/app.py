"""Tiniest possible open-infra example app: greet over HTTP on $PORT."""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

GREETING = os.environ.get("GREETING", "hello")
PORT = int(os.environ.get("PORT", "8080"))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(f"{GREETING}\n".encode())

    def log_message(self, *_):  # quiet logs; Loki captures stdout anyway
        pass


if __name__ == "__main__":
    print(f"listening on :{PORT}")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
