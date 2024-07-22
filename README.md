# HMAC Authentication Client

This Python class, `HMACAuthClient`, is used to create a client that can send HTTP POST requests with HMAC-SHA256 authentication.

## Class Properties

- `host`: The host URL of the server.
- `path`: The path of the API endpoint.
- `uri`: The full URI of the API endpoint.
- `application_id`: The application ID for HMAC authentication.
- `secret`: The secret key for HMAC authentication.

## Methods

- `post(body: str) -> dict`: This method sends a POST request to the server with the provided body. The body should be a JSON-formatted string. The method returns the server's response.

## Usage Example

```python
client = HMACAuthClient("http://localhost:5000", "/api/resource", "your_application_id", "your_secret_access_key")
response = client.post('{"message": "Hello, World!"}')
print(response.text)
```

# HMAC Authentication Server

This Python script creates a server that can authenticate HTTP POST requests using HMAC-SHA256.

## Shared Keys

- `APPLICATION_ID`: The application ID for HMAC authentication.
- `SECRET`: The secret key for HMAC authentication.

## Function: `verify_request`

This function verifies the authenticity of the request. It takes the following parameters:

- `http_method`: The HTTP method of the request.
- `application_id`: The application ID from the request headers.
- `nonce`: The nonce from the request headers.
- `request_uri`: The full URI of the request.
- `request_timestamp`: The timestamp of the request from the headers.
- `request_body`: The body of the request.
- `provided_signature`: The signature from the request headers.
- `secret`: The shared secret key.

The function returns `True` if the provided signature matches the expected signature, and `False` otherwise.

## Route: `/api/resource`

This route accepts POST requests. It extracts the necessary information from the request headers and body, verifies the request, and returns a JSON response indicating whether the request is authenticated.

## Running the Server

The server is run with Flask's built-in server for development purposes.

```python
if __name__ == '__main__':
    app.run(debug=True)
