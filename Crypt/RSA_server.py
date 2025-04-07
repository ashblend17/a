import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Load private key
with open("rsa_private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

# Decrypt function
cipher_rsa = PKCS1_OAEP.new(private_key)

# Set up socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 9999))
server_socket.listen(1)
print("🔐 Server listening on port 9999...")

conn, addr = server_socket.accept()
print(f"🔗 Connection from {addr}")

# Receive and decrypt
encrypted_data = conn.recv(4096)
decrypted_data = cipher_rsa.decrypt(encrypted_data)

print("✅ Decrypted message from client:", decrypted_data.decode())
conn.close()