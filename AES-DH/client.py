import socket
import secrets
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Step 1: Connect to server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 12345))
print("[CLIENT] Connected to the server.")

# Step 2: Receive server's public parameters (P, G, server_public_key)
P, G, server_public_key = map(int, client.recv(1024).decode().split(','))
print(f"[CLIENT] Received public parameters:\n  P = {P}\n  G = {G}\n  Server Public Key = {server_public_key}")

# Step 3: Generate client's private key
client_private_key = secrets.randbelow(P)
print(f"[CLIENT] Generated private key: {client_private_key}")

# Step 4: Compute client's public key
client_public_key = pow(G, client_private_key, P)
print(f"[CLIENT] Computed public key: {client_public_key}")

# Step 5: Send client's public key to server
client.sendall(str(client_public_key).encode())
print("[CLIENT] Sent public key to server.")

# Step 6: Compute shared secret
shared_secret = pow(server_public_key, client_private_key, P)
print(f"[CLIENT] Computed shared secret (before hashing): {shared_secret}")

# Step 7: Derive 256-bit AES key from shared secret using SHA-256
aes_key = hashlib.sha256(str(shared_secret).encode()).digest()
print(f"[CLIENT] Derived AES-256 key: {aes_key.hex()}")

# Function to encrypt messages
def encrypt_message(message, key):
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    print(f"[CLIENT] Encrypting message: '{message}' -> Ciphertext: {ciphertext.hex()}")
    return iv + ciphertext  # Include IV for decryption

# Function to decrypt messages
def decrypt_message(ciphertext, key):
    iv, encrypted_data = ciphertext[:16], ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(encrypted_data), AES.block_size).decode()
    print(f"[CLIENT] Decrypting received message -> Plaintext: '{decrypted_text}'")
    return decrypted_text

# Step 8: Encrypt and send message to server
message = "Hello, Server!"
encrypted_message = encrypt_message(message, aes_key)
client.sendall(encrypted_message)
print(f"[CLIENT] Sent encrypted message to server.")

# Step 9: Receive and decrypt response from server
encrypted_response = client.recv(1024)
print(f"[CLIENT] Received encrypted response: {encrypted_response.hex()}")

decrypted_response = decrypt_message(encrypted_response, aes_key)
print(f"[CLIENT] Decrypted server response: '{decrypted_response}'")

client.close()
print("[CLIENT] Connection closed.")
