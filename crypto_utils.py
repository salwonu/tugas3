# =================== cryptoutil.py ===================

import os
from typing import Tuple
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

# ---- RSA ----
def generate_rsa_keypair(bits: int = 2048) -> Tuple[bytes, bytes]:
    key = RSA.generate(bits)
    priv = key.export_key()
    pub = key.publickey().export_key()
    return priv, pub

def rsa_encrypt(public_pem: bytes, data: bytes) -> bytes:
    key = RSA.import_key(public_pem)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(data)

def rsa_decrypt(private_pem: bytes, ciphertext: bytes) -> bytes:
    key = RSA.import_key(private_pem)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext)

# ---- AES ----
AES_KEY_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16

def generate_aes_key() -> bytes:
    return os.urandom(AES_KEY_SIZE)

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ct

def aes_decrypt(key: bytes, payload: bytes) -> bytes:
    nonce = payload[:NONCE_SIZE]
    tag = payload[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ct = payload[NONCE_SIZE + TAG_SIZE:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)
