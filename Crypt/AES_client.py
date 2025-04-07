import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import base64

# Shared secret key (must match server's key)
key = b'ThisIsASecretKey'

def encrypt_message(message):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    encrypted = base64.b64encode(iv + ct_bytes)
    return encrypted

# Connect to server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 9999))

# Encrypt and send message
msg = "Hello Secure Server!"
encrypted_msg = encrypt_message(msg)
print(f"Sending encrypted: {encrypted_msg}")
client_socket.send(encrypted_msg)

client_socket.close()
