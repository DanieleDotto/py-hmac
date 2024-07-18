import base64
import hashlib
import hmac
from flask import Flask, request, jsonify

app = Flask(__name__)

# Chiavi condivise
APPLICATION_ID = "your_application_id"
SECRET = "your_secret_access_key"

def verify_request(http_method, application_id, nonce, request_uri, request_timestamp, request_body, provided_signature, secret):
    # Convert to uppercase for the HTTP method
    http_method = http_method.upper()

    # Compute the SHA256 hash of the request body
    body_digest = hashlib.sha256(request_body.encode('utf-8')).digest()
    body_hash = base64.b64encode(body_digest).decode('utf-8')

    # Create the string to sign
    string_to_sign = f"{http_method}\n{application_id}\n{nonce}\n{request_uri}\n{request_timestamp}\n{body_hash}"

    # Generate HMAC-SHA256 signature
    decoded_secret = secret.encode('utf-8')
    signature_digest = hmac.new(decoded_secret, string_to_sign.encode('utf-8'), hashlib.sha256).digest()
    expected_signature = base64.b64encode(signature_digest).decode('utf-8')

    # Print the string to sign and the expected signature for debugging
    print("String to Sign (Server):", string_to_sign)
    print("Expected Signature (Server):", expected_signature)

    # Compare the provided signature with the expected signature
    return hmac.compare_digest(provided_signature, expected_signature)

@app.route('/api/resource', methods=['POST'])
def api_resource():
    http_method = request.method
    application_id = request.headers.get('x-application-id')
    nonce = request.headers.get('x-nonce')
    request_uri = request.url
    request_timestamp = request.headers.get('x-request-timestamp')
    provided_signature = request.headers.get('x-signature')
    request_body = request.data.decode('utf-8')

    if application_id != APPLICATION_ID:
        return jsonify({"message": "Invalid application ID"}), 401

    if verify_request(http_method, application_id, nonce, request_uri, request_timestamp, request_body, provided_signature, SECRET):
        return jsonify({"message": "Request is authenticated"})
    else:
        return jsonify({"message": "Request authentication failed"}), 401

if __name__ == '__main__':
    app.run(debug=True)
