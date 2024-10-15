import socket
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP


def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def encrypt_with_rsa(public_key, session_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.encrypt(session_key)


def encrypt_file(file_path, session_key):
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    with open(file_path, 'rb') as f:
        file_data = f.read()
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)
    return cipher_aes.nonce, ciphertext, tag


def send_file_to_server(server_ip, server_port, file_path):
    # Generate RSA key pair
    private_key, public_key = generate_rsa_key_pair()

    # Establish socket connection
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    try:
        # Send public key to the server
        client_socket.sendall(public_key)

        # Receive encrypted session key from server
        encrypted_session_key = client_socket.recv(256)

        # Decrypt session key
        rsa_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        session_key = cipher_rsa.decrypt(encrypted_session_key)

        # Encrypt the file
        nonce, ciphertext, tag = encrypt_file(file_path, session_key)

        # Send file nonce, ciphertext, and tag
        client_socket.sendall(nonce)
        client_socket.sendall(ciphertext)
        client_socket.sendall(tag)

        print("File sent successfully!")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client_socket.close()


if __name__ == "__main__":
    server_ip = "127.0.0.1"  # Replace with actual server IP
    server_port = 1234  # Replace with the server's listening port
    file_path = "file_to_send.txt"  # Replace with the file you want to send
    send_file_to_server(server_ip, server_port, file_path)
