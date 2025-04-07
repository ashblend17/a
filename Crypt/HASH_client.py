import socket
import hashlib
import pickle

message = "Hello Server, this is client.".encode()

# Create SHA-256 hash of the message
hash_object = hashlib.sha256(message)
message_hash = hash_object.hexdigest()

# Pack data to send (message + hash)
data = pickle.dumps((message, message_hash))

# Send to server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 9999))
client_socket.send(data)
print("✅ Message and hash sent to server.")
client_socket.close()
