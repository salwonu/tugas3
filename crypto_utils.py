import os
from typing import Tuple
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES
from Crypto.Util.Padding import pad, unpad

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

DES_KEY_SIZE = 8   
BLOCK_SIZE = 8     

def generate_des_key() -> bytes:
    return os.urandom(DES_KEY_SIZE)

def des_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(8)  
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
    return iv + ciphertext  

def des_decrypt(key: bytes, payload: bytes) -> bytes:
    iv = payload[:8]
    ciphertext = payload[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
    return plaintext
