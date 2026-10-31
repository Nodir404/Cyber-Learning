# Burp Authentication Lab

## Overview

This local educational lab demonstrates Broken Access Control. The vulnerable
server trusts the user-controlled `role` query parameter, while the secure
server derives the role from a server-side session instead.

The vulnerable implementation is retained for comparison. It contains no real
users, passwords, API keys, or production secrets.

## Features

- Deliberately vulnerable access-control example in `server.py`.
- Server-side session example in `secure_server.py`.
- Automated regression tests in `test_secure_server.py`.
- Localhost-only HTTP binding on `127.0.0.1:8000`.
- Burp Repeater-compatible HTTP endpoints.

## Requirements

- Python 3.10 or newer.
- Burp Suite is optional; `curl` can be used for basic checks.

## Installation

No third-party packages are required. From this directory:

```bash
python3 -m py_compile server.py secure_server.py test_secure_server.py
```

## Usage

Run the vulnerable demonstration:

```bash
python3 server.py
```

In Burp Repeater, send:

```http
GET /?role=user HTTP/1.1
Host: 127.0.0.1:8000
```

Then change only `role=user` to `role=admin` and resend. The vulnerable
server returns the administrative demo response because it trusts the URL.
Stop the server with Ctrl+C before starting another server on port 8000.

Run the secure implementation:

```bash
python3 secure_server.py
```

With no session cookie, both `/?role=user` and `/?role=admin` return the
user response. The secure implementation ignores the URL role value and uses
the server-side session store. `create_session("admin")` is available for the
automated example; it is not an authentication workflow.

## Testing

Run the syntax checks and secure-server tests:

```bash
python3 -m py_compile server.py secure_server.py test_secure_server.py
python3 -m unittest -v test_secure_server.py
```

The tests verify that changing `role=user` to `role=admin` does not escalate a
user and that a server-created administrative session is recognized.

## Security considerations

`server.py` is intentionally insecure and must never be used in production.
Real applications must authenticate users, validate authorization on the
server, protect session cookies, use HTTPS, and apply appropriate session
expiration and revocation.

The secure example improves role handling but is still a teaching aid. Its
in-memory session store is not persistent or shared between processes, and it
does not implement login, logout, CSRF protection, cookie attributes, or
session expiration.

## Limitations

The server is designed for local demonstrations only and binds to
`127.0.0.1:8000`. It does not provide a complete authentication system or
represent a production deployment.
