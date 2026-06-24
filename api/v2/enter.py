from http.server import BaseHTTPRequestHandler
import json
import time
import hashlib
import base64
import hmac
from urllib.parse import urlparse, parse_qs

def base32_decode(secret):
    """Decode Base32 string (with padding handling)"""
    # Add padding if needed
    padding = 8 - (len(secret) % 8)
    if padding != 8:
        secret += "=" * padding
    return base64.b32decode(secret)

def generate_totp(secret, interval=30, digits=6):
    """Generate TOTP code from base32 secret"""
    try:
        key = base32_decode(secret)
    except:
        # Try without padding
        key = base64.b32decode(secret + "========")

    counter = int(time.time()) // interval
    counter_bytes = counter.to_bytes(8, 'big')

    # HMAC-SHA1
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    truncated = (
        (hmac_hash[offset] & 0x7F) << 24 |
        (hmac_hash[offset + 1] & 0xFF) << 16 |
        (hmac_hash[offset + 2] & 0xFF) << 8 |
        (hmac_hash[offset + 3] & 0xFF)
    )

    code = truncated % (10 ** digits)
    return str(code).zfill(digits)

class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        try:
            parsed_path = urlparse(self.path)
            query_params = parse_qs(parsed_path.query)

            secret = query_params.get("secret", [None])[0]

            if not secret:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()

                self.wfile.write(json.dumps({
                    "status": False,
                    "message": "secret parameter is required"
                }).encode())
                return

            # Clean secret
            secret_clean = secret.replace(" ", "").upper()

            # Generate OTP
            otp = generate_totp(secret_clean)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            self.wfile.write(json.dumps({
                "status": True,
                "otp": otp
            }).encode())

        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            self.wfile.write(json.dumps({
                "status": False,
                "error": str(e)
            }).encode())
