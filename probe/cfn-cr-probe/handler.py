import http.server, json, os
class H(http.server.BaseHTTPRequestHandler):
    def _ok(self, body=b''):
        self.send_response(200); self.send_header('Content-Type','application/json')
        self.send_header('Content-Length', str(len(body))); self.end_headers()
        if body: self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0) or 0)
        self.rfile.read(n)
        self._ok(json.dumps({"Status":"SUCCESS","PhysicalResourceId":"cfn-cr-probe",
                             "Data":{"Endpoint":"https://cfn-cr-probe.ok"}}).encode())
    def do_GET(self): self._ok()  # Knative readiness
    def log_message(self, *a): pass
http.server.HTTPServer(('', int(os.environ.get('PORT','8080'))), H).serve_forever()
