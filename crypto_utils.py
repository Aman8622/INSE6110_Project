from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
from datetime import datetime, timezone

def print_step(title, data, indent=0):
    prefix = "│  " * indent
    print(f"{prefix}├─ {title}")
    if isinstance(data, bytes):
        data = data.hex()
    print(f"{prefix}│  Value: {data[:64]}...")
    print(f"{prefix}│  Length: {len(data)} bytes")

def load_cert(cert_path):
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def verify_cert(peer_cert, ca_cert):
    print("\n🔐 Certificate Verification:")
    try:
        # Verify certificate signature
        ca_pubkey = ca_cert.public_key()
        ca_pubkey.verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            peer_cert.signature_hash_algorithm
        )
        
        # Verify validity period using UTC-aware properties
        now = datetime.now(timezone.utc)
        if now < peer_cert.not_valid_before_utc:
            raise ValueError(f"Certificate not valid until {peer_cert.not_valid_before_utc}")
        if now > peer_cert.not_valid_after_utc:
            raise ValueError(f"Certificate expired on {peer_cert.not_valid_after_utc}")
            
        print_step("Subject", peer_cert.subject.rfc4514_string(), 1)
        print_step("Issuer", peer_cert.issuer.rfc4514_string(), 1)
        print_step("Valid From (UTC)", peer_cert.not_valid_before_utc.isoformat(), 1)
        print_step("Valid To (UTC)", peer_cert.not_valid_after_utc.isoformat(), 1)
        print("│  └─ ✅ Certificate valid")
        return True
    except Exception as e:
        print(f"│  └─ ❌ Certificate invalid: {str(e)}")
        return False

def encrypt_message(receiver_pubkey, plaintext):
    print("\n🔒 Message Encryption Process:")
    aes_key = os.urandom(16)
    print_step("Generated AES-128 Key", aes_key)
    
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext.encode())
    print_step("AES Nonce", cipher_aes.nonce)
    print_step("AES Tag", tag)
    print_step("AES Ciphertext", ciphertext)
    
    cipher_rsa = PKCS1_OAEP.new(receiver_pubkey)
    enc_aes_key = cipher_rsa.encrypt(aes_key)
    print_step("RSA Encrypted AES Key", enc_aes_key)
    
    package = enc_aes_key + cipher_aes.nonce + tag + ciphertext
    return base64.b64encode(package).decode()

def decrypt_message(private_key, encrypted_data):
    print("\n🔓 Message Decryption Process:")
    data = base64.b64decode(encrypted_data)
    print_step("Received Package", data)
    
    enc_aes_key = data[:256]
    nonce = data[256:272]
    tag = data[272:288]
    ciphertext = data[288:]
    
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)
    print_step("Decrypted AES Key", aes_key)
    
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

def sign_message(private_key, message):
    print("\n✍️ Message Signing:")
    h = SHA256.new(message.encode())
    print_step("Message Hash", h.hexdigest())
    signature = pkcs1_15.new(private_key).sign(h)
    print_step("RSA Signature", signature)
    return base64.b64encode(signature).decode()

def verify_signature(public_key, message, signature):
    print("\n🔍 Signature Verification:")
    h = SHA256.new(message.encode())
    print_step("Computed Hash", h.hexdigest(), 1)
    received_sig = base64.b64decode(signature)
    print_step("Received Signature", received_sig, 1)
    
    try:
        pkcs1_15.new(public_key).verify(h, received_sig)
        print("│  └─ ✅ Signature valid")
        return True
    except Exception as e:
        print(f"│  └─ ❌ Signature invalid: {str(e)}")
        return False