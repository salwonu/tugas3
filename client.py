import socket
import threading
from crypto_utils import rsa_encrypt, generate_des_key, des_encrypt, des_decrypt

def send_packet(sock, data: bytes):
    length = len(data).to_bytes(4, 'big')
    sock.send(length + data)

def recv_packet(sock):
    header = sock.recv(4)
    if not header:
        return None
    length = int.from_bytes(header, 'big')
    return sock.recv(length)

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

public_key = recv_packet(sock)
if not public_key:
    print("[!] Failed to receive public key!")
    exit()

des_key = generate_des_key()
encrypted_key = rsa_encrypt(public_key, des_key)
send_packet(sock, encrypted_key)

username = input("Enter your username: ").strip()
encrypted_username = des_encrypt(des_key, username.encode())
send_packet(sock, encrypted_username)

print(f"[+] Logged in as {username}")
print("💬 Chat started. Type messages below.\n")

def receive_messages():
    while True:
        try:
            encrypted_msg = recv_packet(sock)
            if not encrypted_msg:
                break

            msg = des_decrypt(des_key, encrypted_msg).decode()
            print(f"\n{msg}")
        except:
            print("[!] Disconnected from server.")
            break


threading.Thread(target=receive_messages, daemon=True).start()

while True:
    try:
        message = input("")
        encrypted = des_encrypt(des_key, message.encode())
        send_packet(sock, encrypted)
    except KeyboardInterrupt:
        print("\n[!] Exiting...")
        sock.close()
        break
