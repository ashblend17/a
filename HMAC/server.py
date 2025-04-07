import socket
import hmac
import hashlib

# Shared secret key (must be securely shared between Alice and Bob)
SECRET_KEY = b'supersecretkey'

def generate_hmac(message: bytes, key: bytes) -> bytes:
    """Generate HMAC for a given message using a shared key and SHA-256."""
    hmac_value = hmac.new(key, message, hashlib.sha256).digest()
    print(f"[SERVER] Generated HMAC for message '{message.decode()}': {hmac_value.hex()}")
    return hmac_value

def verify_hmac(message: bytes, received_hmac: bytes, key: bytes) -> bool:
    """Verify received HMAC matches the expected HMAC for the message."""
    expected_hmac = generate_hmac(message, key)
    is_valid = hmac.compare_digest(expected_hmac, received_hmac)
    print(f"[SERVER] HMAC verification result: {'VALID' if is_valid else 'INVALID'}")
    return is_valid

def start_server(host: str, port: int):
    """Start the server, listen for client messages, and verify HMACs."""
    print(f"[SERVER] Starting server on {host}:{port}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print("[SERVER] Waiting for a connection...")

        conn, addr = server_socket.accept()
        with conn:
            print(f"[SERVER] Connected to {addr}")
            while True:
                # Receive message length (4 bytes)
                msg_length_data = conn.recv(4)
                if not msg_length_data:
                    print("[SERVER] No more data. Closing connection.")
                    break
                msg_length = int.from_bytes(msg_length_data, byteorder='big')
                print(f"[SERVER] Expecting message of length: {msg_length} bytes")

                # Receive message content
                message = conn.recv(msg_length)
                print(f"[SERVER] Received message: {message.decode()}")

                # Receive HMAC (32 bytes for SHA-256)
                received_hmac = conn.recv(32)
                print(f"[SERVER] Received HMAC: {received_hmac.hex()}")

                # Verify message integrity
                if verify_hmac(message, received_hmac, SECRET_KEY):
                    response = b"Message received and verified."
                else:
                    response = b"Message verification failed."

                # Send response back to client
                conn.sendall(response)
                print(f"[SERVER] Sent response: {response.decode()}")

if __name__ == "__main__":
    start_server('127.0.0.1', 65432)  # Run on localhost, port 65432
