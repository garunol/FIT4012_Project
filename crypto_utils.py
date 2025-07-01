!pip install pycryptodome
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from typing import Tuple

# ======== DES CFB MODE ========
def des_encrypt_cfb(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CFB, iv=iv)
    ciphertext = cipher.encrypt(plaintext)
    return iv, ciphertext

def des_decrypt_cfb(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext)

# ======== RSA SIGNING ========
def rsa_sign(data: bytes, private_key_pem: bytes) -> bytes:
    key = RSA.import_key(private_key_pem)
    h = SHA256.new(data)
    return pkcs1_15.new(key).sign(h)

def rsa_verify(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    key = RSA.import_key(public_key_pem)
    h = SHA256.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# ======== RSA ENCRYPTION (OAEP) ========
def rsa_encrypt(data: bytes, public_key_pem: bytes) -> bytes:
    key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    return cipher_rsa.encrypt(data)

def rsa_decrypt(ciphertext: bytes, private_key_pem: bytes) -> bytes:
    key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    return cipher_rsa.decrypt(ciphertext)

# ======== DES KEY GENERATION ========
def generate_des_key():
    return get_random_bytes(8)
