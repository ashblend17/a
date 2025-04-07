import socket
import hmac
import hashlib
import pickle

SECRET_KEY = b'super_secret_key_123'
message = b"Hello from HMAC Client!"

# Generate HMAC
client_hmac = hmac.new(SECRET_KEY, message, hashlib.sha256).hexdigest()

# Send message + HMAC
data = pickle.dumps((message, client_hmac))

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 9999))
client_socket.send(data)
print("✅ Message and HMAC sent to server.")
client_socket.close()
