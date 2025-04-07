import socket, pickle
from crypto_utils import *

# RSA and DSA keys
rsa_pub, rsa_priv = generate_rsa_keys()
dsa_priv, dsa_pub = generate_dsa_keys()

server = socket.socket()
server.bind(('localhost', 12345))
server.listen(1)
print("Server listening...")

conn, addr = server.accept()
print(f"Connected to {addr}")

# Receive data
packet = pickle.loads(conn.recv(8192))

# Decrypt symmetric key
sym_key = rsa_decrypt(rsa_priv, packet['enc_key'])

# Choose decryption method
if packet['cipher_mode'] == 'AES':
    message = aes_decrypt(sym_key, packet['ciphertext'])
elif packet['cipher_mode'] == 'DES':
    message = des_decrypt(sym_key, packet['ciphertext'])
else:
    raise Exception("Unsupported cipher")

# Verify HMAC
verify_hmac(sym_key, packet['ciphertext'], packet['hmac'])

# Verify DSA Signature
verify_signature(dsa_pub, packet['ciphertext'], packet['signature'])

print("Decrypted Message:", message.decode())
print("SHA256 Hash:", packet['hash'])

conn.close()
server.close()
