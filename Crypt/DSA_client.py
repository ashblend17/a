import socket
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import pickle

# Generate or load DSA keys
key = DSA.generate(2048)

# Save public key to file (for server)
with open("dsa_public.pem", "wb") as f:
    f.write(key.publickey().export_key())

# Sign message
message = b"Hello from Client with DSA!"
hash_obj = SHA256.new(message)
signer = DSS.new(key, 'fips-186-3')
signature = signer.sign(hash_obj)

# Send message and signature
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 9999))
client_socket.send(pickle.dumps((message, signature)))

client_socket.close()
