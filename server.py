import socket
import threading
from crypto_utils import generate_rsa_keypair, rsa_decrypt, des_encrypt, des_decrypt

HOST = "0.0.0.0"
PORT = 5555

clients = {}  

private_key, public_key = generate_rsa_keypair()
print("[+] RSA keypair generated.")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

print(f"[+] Server running at: {socket.gethostbyname(socket.gethostname())}:{PORT}")


def send_packet(client_socket, data: bytes):
    """Send packet with length header"""
    length = len(data).to_bytes(4, 'big')
    client_socket.send(length + data)


def recv_packet(client_socket):
    """Receive packet with length header"""
    header = client_socket.recv(4)
    if not header:
        return None
    length = int.from_bytes(header, 'big')
    return client_socket.recv(length)


def broadcast(sender_socket, message: str):
    for client_socket, (username, key) in clients.items():
        if client_socket != sender_socket:
            encrypted = des_encrypt(key, message.encode())
            send_packet(client_socket, encrypted)


def handle_client(client_socket):
    try:
        # Receive encrypted DES key
        encrypted_key = recv_packet(client_socket)
        des_key = rsa_decrypt(private_key, encrypted_key)

        # Receive username
        encrypted_username = recv_packet(client_socket)
        username = des_decrypt(des_key, encrypted_username).decode()

        clients[client_socket] = (username, des_key)
        print(f"[+] {username} connected.")

        broadcast(client_socket, f"{username} joined the chat")

        while True:
            encrypted_msg = recv_packet(client_socket)
            if not encrypted_msg:
                break

            msg = des_decrypt(des_key, encrypted_msg).decode()
            print(f"[{username}] {msg}")

            broadcast(client_socket, f"{username}: {msg}")

    except Exception as e:
        print(f"[!] Error: {e}")

    print(f"[X] {clients[client_socket][0]} disconnected.")
    broadcast(client_socket, f"{clients[client_socket][0]} left the chat")

    del clients[client_socket]
    client_socket.close()


def accept_clients():
    while True:
        client_socket, addr = server.accept()
        print(f"[+] New connection from {addr}")

        send_packet(client_socket, public_key)

        threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()


accept_clients()
