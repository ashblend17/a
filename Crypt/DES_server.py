import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import base64

# DES key (8 bytes)
key = b'8bytekey'

def decrypt_message(enc_message):
    enc_message = base64.b64decode(enc_message)
    iv = enc_message[:8]  # DES block size is 8
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(enc_message[8:]), DES.block_size)
    return decrypted.decode()

# Server setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 9999))
server_socket.listen(1)
print("DES Server is listening...")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

data = conn.recv(1024)
if data:
    print(f"Encrypted message: {data}")
    message = decrypt_message(data)
    print(f"Decrypted message: {message}")

conn.close()
