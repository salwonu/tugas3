# =================== client.py ===================

import socket
import threading
from crypto_utils import rsa_encrypt, generate_aes_key, aes_encrypt, aes_decrypt

# ---- Packet util ----
def send_packet(sock, data: bytes):
    length = len(data).to_bytes(4, 'big')
    sock.send(length + data)

def recv_packet(sock):
    header = sock.recv(4)
    if not header:
        return None
    length = int.from_bytes(header, 'big')
    return sock.recv(length)

# ---- Input server address ----
server_ip = input("Server IP: ").strip()
port_input = input("Port [5555]: ").strip()
PORT = int(port_input) if port_input else 5555

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print(f"[+] Connecting to {server_ip}:{PORT} ...")

try:
    sock.connect((server_ip, PORT))
    print("[+] Connected!")
except:
    print("[!] Connection failed. Make sure both devices are on same WiFi / hotspot.")
    exit()

# ---- Step 1: Receive RSA Public Key ----
public_key = recv_packet(sock)
if not public_key:
    print("[!] Failed to receive public key!")
    exit()

# ---- Step 2: Generate AES key and send encrypted ----
aes_key = generate_aes_key()
encrypted_key = rsa_encrypt(public_key, aes_key)
send_packet(sock, encrypted_key)

# ---- Step 3: Send username encrypted ----
username = input("Enter your username: ").strip()
encrypted_username = aes_encrypt(aes_key, username.encode())
send_packet(sock, encrypted_username)

print(f"[+] Logged in as {username}")
print("💬 Chat started. Type messages below.\n")


# ---- Receiving messages ----
def receive_messages():
    while True:
        try:
            encrypted_msg = recv_packet(sock)
            if not encrypted_msg:
                break

            msg = aes_decrypt(aes_key, encrypted_msg).decode()
            print(f"\n{msg}")
        except:
            print("[!] Disconnected from server.")
            break


threading.Thread(target=receive_messages, daemon=True).start()


# ---- Chat send loop ----
while True:
    try:
        message = input("")
        encrypted = aes_encrypt(aes_key, message.encode())
        send_packet(sock, encrypted)
    except KeyboardInterrupt:
        print("\n[!] Exiting...")
        sock.close()
        break
