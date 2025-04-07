import socket, pickle
from crypto_utils import *

# Message and encryption choice
message = b"Top secret message!"
cipher_mode = 'DES'  # or 'AES'

# Keys
rsa_pub, _ = generate_rsa_keys()      # in real use, get server's public RSA key
dsa_priv, dsa_pub = generate_dsa_keys()

# Symmetric key
sym_key = os.urandom(32) if cipher_mode == 'AES' else crypto_random(8)

# Encrypt message
if cipher_mode == 'AES':
    ciphertext = aes_encrypt(sym_key, message)
else:
    ciphertext = des_encrypt(sym_key, message)

# HMAC and hash
hmac_tag = create_hmac(sym_key, ciphertext)
hash_val = sha256_hash(message)

# Encrypt symmetric key with RSA
enc_key = rsa_encrypt(rsa_pub, sym_key)

# Sign the ciphertext
signature = sign_data(dsa_priv, ciphertext)

# Send packet
packet = {
    'cipher_mode': cipher_mode,
    'ciphertext': ciphertext,
    'enc_key': enc_key,
    'hmac': hmac_tag,
    'hash': hash_val,
    'signature': signature,
}

client = socket.socket()
client.connect(('localhost', 12345))
client.send(pickle.dumps(packet))
client.close()
