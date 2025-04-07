import socket
import secrets
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Step 1: Define large prime P and generator G (public parameters)
P = 23  # This should be a much larger prime in real applications
G = 5   # Common generator
print(f"[SERVER] Using public parameters:\n  P (Prime) = {P}\n  G (Generator) = {G}")

# Step 2: Generate server's private key (random number)
server_private_key = secrets.randbelow(P)
print(f"[SERVER] Generated private key: {server_private_key}")

# Step 3: Compute server's public key
server_public_key = pow(G, server_private_key, P)
print(f"[SERVER] Computed public key: {server_public_key}")

# Step 4: Start server and wait for a connection
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 12345))
server.listen(1)
print("[SERVER] Listening for incoming connections...")

conn, addr = server.accept()
print(f"[SERVER] Connection established with {addr}")

# Step 5: Send public parameters (P, G, server_public_key) to client
public_data = f"{P},{G},{server_public_key}"
conn.sendall(public_data.encode())
print("[SERVER] Sent public parameters and public key to client.")

# Step 6: Receive client's public key
client_public_key = int(conn.recv(1024).decode())
print(f"[SERVER] Received client's public key: {client_public_key}")

# Step 7: Compute shared secret
shared_secret = pow(client_public_key, server_private_key, P)
print(f"[SERVER] Computed shared secret (before hashing): {shared_secret}")

# Step 8: Derive 256-bit AES key from shared secret using SHA-256
aes_key = hashlib.sha256(str(shared_secret).encode()).digest()
print(f"[SERVER] Derived AES-256 key: {aes_key.hex()}")

# Function to encrypt messages
def encrypt_message(message, key):
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    print(f"[SERVER] Encrypting message: '{message}' -> Ciphertext: {ciphertext.hex()}")
    return iv + ciphertext  # Include IV for decryption

# Function to decrypt messages
def decrypt_message(ciphertext, key):
    iv, encrypted_data = ciphertext[:16], ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(encrypted_data), AES.block_size).decode()
    print(f"[SERVER] Decrypting received message -> Plaintext: '{decrypted_text}'")
    return decrypted_text

# Step 9: Receive and decrypt message from client
encrypted_message = conn.recv(1024)
print(f"[SERVER] Received encrypted message: {encrypted_message.hex()}")

decrypted_message = decrypt_message(encrypted_message, aes_key)
print(f"[SERVER] Decrypted client message: '{decrypted_message}'")

# Step 10: Encrypt and send response
response = "Hello, Client!"
encrypted_response = encrypt_message(response, aes_key)
conn.sendall(encrypted_response)
print(f"[SERVER] Sent encrypted response to client.")

conn.close()
server.close()
print("[SERVER] Connection closed.")
