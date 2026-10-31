# Burp Suite: local access-control lab

This deliberately insecure **educational** HTTP server demonstrates why a backend must not trust `role=admin` in a query string. It has no real users or secrets.

## Run
```bash
python3 -m py_compile server.py
python3 server.py
```

Only binds to `127.0.0.1:8000`, not the local network.

## Test in Burp Repeater
```http
GET /?role=user HTTP/1.1
Host: 127.0.0.1:8000
```
Then replace `role=user` with `role=admin` and resend. Compare the response bodies.

This is a purposefully vulnerable lab; a production system must validate identity and authorization on the server, not trust query parameters.

Stop with Ctrl+C.
