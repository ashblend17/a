# client_alice_verbose.py

import socket
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization, hashes

print("=== Alice (Client) Starting ===")

# Step 1: Generate Alice's DSA key pair
print("\n[Step 1] Generating Alice's DSA key pair...")
alice_private_key = dsa.generate_private_key(key_size=2048)
alice_public_key = alice_private_key.public_key()
print("-> Alice's DSA key pair generated.")

# Step 2: Serialize Alice's public key
print("\n[Step 2] Serializing Alice's public key to PEM format...")
alice_public_pem = alice_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print(f"-> Alice's Public Key:\n{alice_public_pem.decode()}")

# Step 3: Connect to Bob's server
print("\n[Step 3] Connecting to Bob (localhost:5000)...")
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 5000))
print("-> Connected to Bob.")

# Step 4: Receive Bob's public key
print("\n[Step 4] Receiving Bob's public key...")
bob_public_pem = client_socket.recv(2048)
bob_public_key = serialization.load_pem_public_key(bob_public_pem)
print(f"-> Received Bob's Public Key:\n{bob_public_pem.decode()}")

# Step 5: Send Alice's public key to Bob
print("\n[Step 5] Sending Alice's public key to Bob...")
client_socket.sendall(alice_public_pem)
print("-> Alice's public key sent.")

# Step 6: Alice prepares signed message
print("\n[Step 6] Preparing message to send to Bob...")
alice_message = b"Hello Bob, this is Alice!"
print(f"-> Message: {alice_message.decode()}")

print("-> Signing message with Alice's private key...")
alice_signature = alice_private_key.sign(
    alice_message,
    hashes.SHA256()
)
print(f"-> Generated signature: {alice_signature.hex()}")

print("\n[Step 7] Sending signed message to Bob...")
client_socket.sendall(alice_message + b'||' + alice_signature)
print("-> Signed message sent.")

# Step 8: Receive signed message from Bob
print("\n[Step 8] Waiting for Bob's reply...")
data = client_socket.recv(2048)
message, signature = data.split(b'||')
print(f"-> Received message: {message.decode()}")
print(f"-> Received signature: {signature.hex()}")

# Step 9: Verify Bob's signature
print("\n[Step 9] Verifying Bob's signature...")
try:
    bob_public_key.verify(
        signature,
        message,
        hashes.SHA256()
    )
    print("✅ Signature verified! Message authenticity confirmed.")
    print(f"Bob's message: {message.decode()}")
except Exception as e:
    print("❌ Signature verification failed:", e)

print("\n[Step 10] Closing connection...")
client_socket.close()
print("=== Alice (Client) Shutting Down ===")
