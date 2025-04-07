import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

def start_server():
    
    rsa_key = RSA.generate(2048)
    private_key = rsa_key
    public_key = rsa_key.publickey()
    print("Generated RSA key pair (pvt/pub): ", private_key, "& ",public_key)

    # Create a server socket listening on localhost:65432.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Server listening on port 12345...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")


    public_key_pem = public_key.export_key()
    conn.sendall(public_key_pem)
    print("Sent RSA public key to client.")



    encrypted_aes_key = conn.recv(256)
    print("Received encrypted AES key.")


    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    print("AES key decrypted.")



    nonce = conn.recv(16)
    tag = conn.recv(16)
    ciphertext_length_bytes = conn.recv(4)
    ciphertext_length = int.from_bytes(ciphertext_length_bytes, byteorder='big')

    ciphertext = b""
    while len(ciphertext) < ciphertext_length:
        chunk = conn.recv(ciphertext_length - len(ciphertext))
        if not chunk:
            break
        ciphertext += chunk
    print("Received encrypted message.")


    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    try:
        decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
        print("Decrypted message:", decrypted_message.decode())
    except ValueError:
        print("Decryption failed or message tampered with.")

    conn.close()
    server_socket.close()

if __name__ == '__main__':
    start_server()
