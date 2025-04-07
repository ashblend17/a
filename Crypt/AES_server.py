import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

# Shared secret key (must be 16, 24, or 32 bytes)
key = b'ThisIsASecretKey'

def decrypt_message(enc_message):
    enc_message = base64.b64decode(enc_message)
    iv = enc_message[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(enc_message[16:]), AES.block_size)
    return decrypted.decode()

# Set up server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 9999))
server_socket.listen(1)

print("Server is listening...")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

data = conn.recv(1024)
if data:
    print(f"Encrypted message received: {data}")
    message = decrypt_message(data)
    print(f"Decrypted message: {message}")

conn.close()
