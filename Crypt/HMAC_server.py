import socket
import hmac
import hashlib
import pickle

SECRET_KEY = b'super_secret_key_123'

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 9999))
server_socket.listen(1)
print("🔐 HMAC Server is listening...")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

# Receive data
data = conn.recv(4096)
message, client_hmac = pickle.loads(data)

# Recalculate HMAC
server_hmac = hmac.new(SECRET_KEY, message, hashlib.sha256).hexdigest()

# Compare
if hmac.compare_digest(server_hmac, client_hmac):
    print("✅ Message integrity verified.")
    print("📩 Message from client:", message.decode())
else:
    print("❌ HMAC mismatch! Message may be tampered or unauthenticated.")

conn.close()
