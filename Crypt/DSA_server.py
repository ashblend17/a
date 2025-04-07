import socket
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import pickle

# Load public key (assume key file already exists)
with open("dsa_public.pem", "rb") as f:
    public_key = DSA.import_key(f.read())

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 9999))
server_socket.listen(1)
print("Server is listening...")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

# Receive message + signature
data = conn.recv(4096)
message, signature = pickle.loads(data)

# Hash and verify
hash_obj = SHA256.new(message)
verifier = DSS.new(public_key, 'fips-186-3')

try:
    verifier.verify(hash_obj, signature)
    print("✅ Signature is valid.")
    print("📩 Message:", message.decode())
except ValueError:
    print("❌ Signature is invalid!")

conn.close()
