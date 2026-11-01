"""Secure variant of the access-control lab using server-side sessions."""
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from secrets import token_urlsafe

SESSION_STORE: dict[str, str] = {}


def create_session(role: str = "user") -> str:
    """Create a server-side session and return its opaque cookie value."""
    session_id = token_urlsafe(32)
    SESSION_STORE[session_id] = role
    return session_id


class SecureLabHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        session_id = self.headers.get("Cookie", "").removeprefix("session_id=")
        role = SESSION_STORE.get(session_id, "user")

        if role == "admin":
            message = "Welcome, Admin! Secure demo access.\n"
        else:
            message = "Welcome, User! Access limited.\n"

        body = message.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print("Secure educational lab: http://127.0.0.1:8000 (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", 8000), SecureLabHandler).serve_forever()
