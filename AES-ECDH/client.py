# client.py
import socket
from common import *

HOST = 'localhost'
PORT = 65432

print("[Client] Generating Alice's ECC key pair...")
alice_private_key = generate_private_key()
alice_public_key = alice_private_key.public_key()
alice_public_key_bytes = serialize_public_key(alice_public_key)
print("[Client] Alice's Public Key (PEM format):")
print(alice_public_key_bytes.decode())

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print(f"[Client] Connecting to {HOST}:{PORT}...")
    s.connect((HOST, PORT))
    print("[Client] Connected to server.")

    # Receive Bob's public key
    bob_public_key_bytes = s.recv(1024)
    print("[Client] Received Bob's public key:")
    print(bob_public_key_bytes.decode())
    bob_public_key = deserialize_public_key(bob_public_key_bytes)

    # Send Alice's public key
    s.sendall(alice_public_key_bytes)
    print("[Client] Sent Alice's public key to Bob.")

    # Derive shared secret
    shared_secret = derive_shared_secret(alice_private_key, bob_public_key)
    print("[Client] Derived shared secret (ECDH exchange).")

    # Derive AES key
    aes_key = get_aes_key(shared_secret)
    print(f"[Client] AES Key (SHA-256 of shared secret x-coordinate): {aes_key.hex()}")

    # Send encrypted message
    message = b"Hello from Alice!"
    encrypted_msg = aes_encrypt(aes_key, message)
    print(f"[Client] Sending encrypted message: {encrypted_msg.hex()}")
    s.sendall(encrypted_msg)

    # Receive encrypted response
    encrypted_response = s.recv(1024)
    print(f"[Client] Received encrypted response: {encrypted_response.hex()}")
    decrypted_response = aes_decrypt(aes_key, encrypted_response)
    print(f"[Client] Decrypted response from Bob: {decrypted_response.decode()}")

    print("[Client] Communication complete.")
