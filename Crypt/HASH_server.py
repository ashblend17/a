import socket
import hashlib
import pickle

# Setup server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 9999))
server_socket.listen(1)
print("Server is listening for client...")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

# Receive message + hash
data = conn.recv(4096)
message, received_hash = pickle.loads(data)

# Recalculate hash
hash_object = hashlib.sha256(message)
calculated_hash = hash_object.hexdigest()

# Verify hash
if calculated_hash == received_hash:
    print("✅ Hash matched. Message is intact.")
    print("📩 Message from client:", message.decode())
else:
    print("❌ Hash mismatch! Message might be tampered.")

conn.close()
