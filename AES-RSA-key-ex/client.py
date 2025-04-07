import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

def start_client():
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))
    print("Connected to server.")

    
    public_key_pem = b""
    
    while b"-----END PUBLIC KEY-----" not in public_key_pem:
        data = client_socket.recv(1024)
        if not data:
            break
        public_key_pem += data
    print("Received RSA public key: ",public_key_pem )

    
    public_key = RSA.import_key(public_key_pem)

    
    aes_key = get_random_bytes(32)
    print("Generated AES key: ", aes_key)

    
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    
    client_socket.sendall(encrypted_aes_key)
    print("Sent encrypted AES key to server.")

    
    message = b"Hola amigos! This is a super secret text message Pls don't hack me."
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)
    nonce = cipher_aes.nonce

    
    client_socket.sendall(nonce)
    client_socket.sendall(tag)
    ciphertext_length = len(ciphertext)
    client_socket.sendall(ciphertext_length.to_bytes(4, byteorder='big'))
    client_socket.sendall(ciphertext)
    print("Sent AES encrypted message to server.")

    client_socket.close()

if __name__ == '__main__':
    start_client()
