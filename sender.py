#%%
import base64
import hashlib
import hmac
import time
import uuid
import requests

class HMACAuthClient:
    def __init__(self, host: str, path: str, application_id: str, secret: str):
        self.__host = self.__validate_host(host)
        self.__path = self.__validate_path(path)
        self.__uri = f"{self.__host}{self.__path}"
        self.__application_id = self.__validate_application_id(application_id)
        self.__secret = self.__validate_secret(secret)
        
    @property
    def host(self) -> str:
        return self.__host
    
    @property
    def path(self) -> str:
        return self.__path
    
    @property
    def uri(self) -> str:
        return self.__uri
    
    @property
    def application_id(self) -> str:
        return self.__application_id
    
    @property
    def secret(self) -> str:
        return self.__secret
    
    def __validate_host(self, host: str) -> str:
        if not host:
            raise ValueError("Host is required")
        if not isinstance(host, str):
            raise ValueError("Host must be a string")
        return host
    
    def __validate_path(self, path: str) -> str:
        if not path:
            raise ValueError("Path is required")
        if not isinstance(path, str):
            raise ValueError("Path must be a string")
        if not path.startswith("/"):
            raise ValueError("Path must start with a forward slash")
        return path
    
    def __validate_application_id(self, application_id: str) -> str:
        if not application_id:
            raise ValueError("Application ID is required")
        if not isinstance(application_id, str):
            raise ValueError("Application ID must be a string")
        return application_id
    
    def __validate_secret(self, secret: str) -> str:
        if not secret:
            raise ValueError("Secret is required")
        if not isinstance(secret, str):
            raise ValueError("Secret must be a string")
        return secret
    
    def post(self, body: str) -> dict:
        http_method = "POST"
        nonce = str(uuid.uuid4())                  # Arbitrary unique value
        request_timestamp = str(int(time.time()))  # Current Unix timestamp
        
        # Compute the SHA256 hash of the http post request body
        body_digest = hashlib.sha256(body.encode('utf-8')).digest()
        body_hash = base64.b64encode(body_digest).decode('utf-8')
        
        # Create the string to sign
        string_to_sign = f"{http_method}\n{self.application_id}\n{nonce}\n{self.uri}\n{request_timestamp}\n{body_hash}"
    
        # Generate HMAC-SHA256 signature
        decoded_secret = self.secret.encode('utf-8')
        signature_digest = hmac.new(decoded_secret, string_to_sign.encode('utf-8'), hashlib.sha256).digest()
        signature = base64.b64encode(signature_digest).decode('utf-8')

        # Print the string to sign and the signature for debugging
        print("String to Sign (Client):", string_to_sign)
        print("Generated Signature (Client):", signature)

        # Prepare headers with the signature
        headers = {
            "x-application-id": self.application_id,
            "x-nonce": nonce,
            "x-request-timestamp": request_timestamp,
            "x-signature": signature,
            "Content-Type": "application/json"
        }
        
        response = requests.post(self.uri, headers=headers, data=body)
        return response

# Esempio di utilizzo
client = HMACAuthClient("http://localhost:5000", "/api/resource", "your_application_id", "your_secret_access_key")
response = client.post('{"message": "Hello, World!"}')
print(response.text)

# %%
