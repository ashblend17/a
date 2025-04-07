# server.py
import socket
from common import *

HOST = 'localhost'
PORT = 65432

print("[Server] Generating Bob's ECC key pair...")
bob_private_key = generate_private_key()
bob_public_key = bob_private_key.public_key()
bob_public_key_bytes = serialize_public_key(bob_public_key)
print("[Server] Bob's Public Key (PEM format):")
print(bob_public_key_bytes.decode())

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[Server] Listening on {HOST}:{PORT}...")

    conn, addr = s.accept()
    with conn:
        print(f"[Server] Connected by {addr}")

        # Send Bob's public key
        conn.sendall(bob_public_key_bytes)
        print("[Server] Sent Bob's public key to Alice.")

        # Receive Alice's public key
        alice_public_key_bytes = conn.recv(1024)
        print("[Server] Received Alice's public key:")
        print(alice_public_key_bytes.decode())
        alice_public_key = deserialize_public_key(alice_public_key_bytes)

        # Derive shared secret
        shared_secret = derive_shared_secret(bob_private_key, alice_public_key)
        print("[Server] Derived shared secret (ECDH exchange).")

        # Derive AES key
        aes_key = get_aes_key(shared_secret)
        print(f"[Server] AES Key (SHA-256 of shared secret x-coordinate): {aes_key.hex()}")

        # Receive encrypted message
        encrypted_msg = conn.recv(1024)
        print(f"[Server] Received encrypted message: {encrypted_msg.hex()}")
        decrypted_msg = aes_decrypt(aes_key, encrypted_msg)
        print(f"[Server] Decrypted message from Alice: {decrypted_msg.decode()}")

        # Respond
        response = b"Hello from Bob!"
        encrypted_response = aes_encrypt(aes_key, response)
        print(f"[Server] Sending encrypted response: {encrypted_response.hex()}")
        conn.sendall(encrypted_response)
        print("[Server] Response sent. Communication complete.")
