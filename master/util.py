from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes as crypto_random
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa, dsa, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import rsa, hashlib, os

# --- AES ---
def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encrypted = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    return iv + encrypted

def aes_decrypt(key, iv_ciphertext):
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decrypted = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted) + unpadder.finalize()

# --- DES ---
def des_encrypt(key, plaintext):
    cipher = DES.new(key, DES.MODE_CBC)
    pad_len = 8 - len(plaintext) % 8
    padded = plaintext + bytes([pad_len]) * pad_len
    return cipher.iv + cipher.encrypt(padded)

def des_decrypt(key, iv_ciphertext):
    iv = iv_ciphertext[:8]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted = cipher.decrypt(iv_ciphertext[8:])
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]

# --- RSA ---
def generate_rsa_keys():
    return rsa.newkeys(2048)

def rsa_encrypt(public_key, data):
    return rsa.encrypt(data, public_key)

def rsa_decrypt(private_key, encrypted_data):
    return rsa.decrypt(encrypted_data, private_key)

# --- HMAC ---
def create_hmac(key, message):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    return h.finalize()

def verify_hmac(key, message, tag):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    h.verify(tag)

# --- Hash ---
def sha256_hash(data):
    return hashlib.sha256(data).hexdigest()

# --- DSA ---
def generate_dsa_keys():
    private_key = dsa.generate_private_key(key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(private_key, message):
    hasher = hashes.SHA256()
    return private_key.sign(message, hashes.SHA256())

def verify_signature(public_key, message, signature):
    public_key.verify(signature, message, hashes.SHA256())
