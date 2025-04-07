import socket
import hmac
import hashlib

# Shared secret key (must be the same as the server)
SECRET_KEY = b'supersecretkey'

def generate_hmac(message: bytes, key: bytes) -> bytes:
    """Generate HMAC for a given message using a shared key and SHA-256."""
    hmac_value = hmac.new(key, message, hashlib.sha256).digest()
    print(f"[CLIENT] Generated HMAC for message '{message.decode()}': {hmac_value.hex()}")
    return hmac_value

def send_message(host: str, port: int, message: str):
    """Send a message with its HMAC to the server."""
    print(f"[CLIENT] Preparing to send message: {message}")
    
    message_bytes = message.encode()
    message_hmac = generate_hmac(message_bytes, SECRET_KEY)

    print(f"[CLIENT] Connecting to server at {host}:{port}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print("[CLIENT] Connected to server.")

        # Send the length of the message (4 bytes)
        msg_length_bytes = len(message_bytes).to_bytes(4, byteorder='big')
        client_socket.sendall(msg_length_bytes)
        print(f"[CLIENT] Sent message length: {len(message_bytes)} bytes")

        # Send the message itself
        client_socket.sendall(message_bytes)
        print(f"[CLIENT] Sent message: {message}")

        # Send the HMAC
        client_socket.sendall(message_hmac)
        print(f"[CLIENT] Sent HMAC: {message_hmac.hex()}")

        # Receive and print the server's response
        response = client_socket.recv(1024)
        print(f"[CLIENT] Received server response: {response.decode()}")

if __name__ == "__main__":
    send_message('127.0.0.1', 65432, "Hello, Bob! This is Alice.")
