from http.server import BaseHTTPRequestHandler
import json
import pyotp
from urllib.parse import urlparse, parse_qs

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            query = parse_qs(urlparse(self.path).query)

            secret = query.get("secret", [None])[0]

            if not secret:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()

                self.wfile.write(json.dumps({
                    "status": False,
                    "message": "secret required"
                }).encode())
                return

            otp = pyotp.TOTP(secret).now()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(json.dumps({
                "status": True,
                "otp": otp
            }).encode())

        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(json.dumps({
                "status": False,
                "error": str(e)
            }).encode())
