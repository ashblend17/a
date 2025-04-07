import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Load public key
with open("rsa_public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

# Encrypt message
message = b"Hello from RSA Client!"
cipher_rsa = PKCS1_OAEP.new(public_key)
encrypted_message = cipher_rsa.encrypt(message)

# Connect and send
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 9999))
client_socket.send(encrypted_message)

print("📤 Encrypted message sent to server.")
client_socket.close()
