# server_bob_verbose.py

import socket
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization, hashes

print("=== Bob (Server) Starting ===")

# Step 1: Generate Bob's DSA key pair
print("\n[Step 1] Generating Bob's DSA key pair...")
bob_private_key = dsa.generate_private_key(key_size=2048)
bob_public_key = bob_private_key.public_key()
print("-> Bob's DSA key pair generated.")

# Step 2: Serialize Bob's public key to send to Alice
print("\n[Step 2] Serializing Bob's public key to PEM format...")
bob_public_pem = bob_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print(f"-> Bob's Public Key:\n{bob_public_pem.decode()}")

# Step 3: Set up TCP server
print("\n[Step 3] Setting up TCP server on localhost:5000...")
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 5000))
server_socket.listen(1)
print("-> Server is now listening for connections...")

# Step 4: Accept connection from Alice
conn, addr = server_socket.accept()
print(f"\n[Step 4] Connection established with {addr} (Alice)")

# Step 5: Send Bob's public key to Alice
print("\n[Step 5] Sending Bob's public key to Alice...")
conn.sendall(bob_public_pem)
print("-> Bob's public key sent.")

# Step 6: Receive Alice's public key
print("\n[Step 6] Receiving Alice's public key...")
alice_public_pem = conn.recv(2048)
alice_public_key = serialization.load_pem_public_key(alice_public_pem)
print(f"-> Received Alice's Public Key:\n{alice_public_pem.decode()}")

# Step 7: Receive signed message from Alice
print("\n[Step 7] Waiting for signed message from Alice...")
data = conn.recv(2048)
message, signature = data.split(b'||')
print(f"-> Received message: {message.decode()}")
print(f"-> Received signature: {signature.hex()}")

# Step 8: Verify Alice's signature
print("\n[Step 8] Verifying Alice's signature...")
try:
    alice_public_key.verify(
        signature,
        message,
        hashes.SHA256()
    )
    print("✅ Signature verified! Message authenticity confirmed.")
    print(f"Alice's message: {message.decode()}")
except Exception as e:
    print("❌ Signature verification failed:", e)

# Step 9: Bob sends signed message back to Alice
print("\n[Step 9] Bob preparing reply message...")
bob_message = b"Hello Alice, message received!"
print(f"-> Message to send: {bob_message.decode()}")

print("-> Signing message with Bob's private key...")
bob_signature = bob_private_key.sign(
    bob_message,
    hashes.SHA256()
)
print(f"-> Generated signature: {bob_signature.hex()}")

print("\n[Step 10] Sending signed message back to Alice...")
conn.sendall(bob_message + b'||' + bob_signature)
print("-> Signed message sent.")

print("\n[Step 11] Closing connection...")
conn.close()
server_socket.close()
print("=== Bob (Server) Shutting Down ===")
