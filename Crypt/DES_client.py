import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import base64

# DES key (8 bytes)
key = b'8bytekey'

def encrypt_message(message):
    iv = get_random_bytes(8)  # DES IV is 8 bytes
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(message.encode(), DES.block_size))
    encrypted = base64.b64encode(iv + ct_bytes)
    return encrypted

# Connect to server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 9999))

# Send encrypted message
message = "Hello Server (DES)"
encrypted_msg = encrypt_message(message)
print(f"Sending encrypted: {encrypted_msg}")
client_socket.send(encrypted_msg)

client_socket.close()
