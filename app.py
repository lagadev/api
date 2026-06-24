from flask import Flask, request, jsonify
import pyotp

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({"status": True, "message": "2FA OTP Generator API is running"})

@app.route('/api/v2/enter')
def generate_otp():
    try:
        secret = request.args.get('secret')
        if not secret:
            return jsonify({"status": False, "message": "secret parameter is required"}), 400

        secret_clean = secret.replace(" ", "").upper()
        totp = pyotp.TOTP(secret_clean)
        otp = totp.now()

        return jsonify({"status": True, "otp": otp})

    except Exception as e:
        return jsonify({"status": False, "error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
