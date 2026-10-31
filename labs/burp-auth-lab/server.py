"""Educational access-control lab. Run on localhost only."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        role = query.get("role", ["user"])[0]

        # Intentionally insecure: trusts a user-controlled query parameter.
        if role == "admin":
            message = "Welcome, Admin! Demo token: LAB-DEMO-123\n"
        else:
            message = "Welcome, User! Access limited.\n"

        body = message.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    print("Educational lab: http://127.0.0.1:8000 (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", 8000), LabHandler).serve_forever()
