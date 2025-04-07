from Crypto.PublicKey import RSA

# Generate 2048-bit RSA key pair
key = RSA.generate(2048)

# Save private key
with open("rsa_private.pem", "wb") as f:
    f.write(key.export_key())

# Save public key
with open("rsa_public.pem", "wb") as f:
    f.write(key.publickey().export_key())

print("✅ RSA key pair generated successfully.")
