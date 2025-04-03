import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from crypto_utils import *

class SecureChatApp:
    def __init__(self, root, user, my_port, peer_port):
        self.root = root
        self.user = user
        self.root.title(f"Secure Chat - {user}")
        
        # Load identity materials
        print(f"\n🔐 Initializing {user}:")
        self.ca_cert = load_cert("ca/ca_cert.pem")
        self.user_cert = load_cert(f"users/{user}_cert.pem")
        
        # Load and convert private key
        with open(f"users/{user}_key.pem", "rb") as f:
            private_key_pem = f.read()
            self.private_key = RSA.import_key(private_key_pem)
        
        self.peer_pubkey = None
        
        # Initialize GUI
        self.chat_area = scrolledtext.ScrolledText(root, wrap=tk.WORD)
        self.input_field = tk.Entry(root)
        self.send_btn = tk.Button(root, text="Send", command=self.send_message)
        
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.input_field.pack(padx=10, pady=5, fill=tk.X)
        self.send_btn.pack(padx=10, pady=5)
        
        # Setup network connection
        self.conn = self.setup_network(my_port, peer_port)
        threading.Thread(target=self.receive_messages, daemon=True).start()
    
    def setup_network(self, my_port, peer_port):
        print(f"\n🌐 Network Setup:")
        try:
            # Try connecting as client first
            print("│  Connecting as client...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('localhost', peer_port))
            print("│  ✅ Connected to peer")
            self.exchange_certificates(sock)
            return sock
        except ConnectionRefusedError:
            # Start as server if connection fails
            print("│  Starting server...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('localhost', my_port))
            sock.listen(1)
            conn, addr = sock.accept()
            print(f"│  ✅ Peer connected from {addr}")
            self.exchange_certificates(conn)
            return conn
    
    def exchange_certificates(self, conn):
        print("\n🔑 Certificate Exchange:")
        # Send our certificate
        conn.send(self.user_cert.public_bytes(serialization.Encoding.PEM))
        print_step("Sent Certificate", 
                 self.user_cert.public_bytes(serialization.Encoding.PEM))
        
        # Receive peer certificate
        peer_cert_pem = conn.recv(4096)
        self.peer_cert = x509.load_pem_x509_certificate(
            peer_cert_pem, 
            default_backend()
        )
        print_step("Received Certificate", peer_cert_pem)
        
        if not verify_cert(self.peer_cert, self.ca_cert):
            raise ValueError("Invalid peer certificate")
        
        # Convert cryptography public key to PyCryptodome format
        peer_pubkey_pem = self.peer_cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.peer_pubkey = RSA.import_key(peer_pubkey_pem)
    
    def send_message(self):
        message = self.input_field.get()
        if not message:
            return
        
        print(f"\n📤 Sending Message:")
        print(f"│  Plaintext: {message}")
        try:
            encrypted = encrypt_message(self.peer_pubkey, message)
            signature = sign_message(self.private_key, message)
            self.conn.send(f"{encrypted}|{signature}".encode())
            self.chat_area.insert(tk.END, f"You: {message}\n")
            self.input_field.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")
    
    def receive_messages(self):
        while True:
            try:
                data = self.conn.recv(4096).decode()
                if not data:
                    break
                
                print(f"\n📩 Received Message:")
                encrypted, signature = data.split("|")
                plaintext = decrypt_message(self.private_key, encrypted)
                verified = verify_signature(self.peer_pubkey, plaintext, signature)
                
                status = "✅ Verified" if verified else "❌ Unverified"
                self.chat_area.insert(tk.END, f"Peer: {plaintext} {status}\n")
            except Exception as e:
                messagebox.showerror("Error", f"Connection error: {str(e)}")
                break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Secure Chat with Certificates')
    parser.add_argument('user', help='User name (alice/bob)')
    parser.add_argument('my_port', type=int, help='Your listening port')
    parser.add_argument('peer_port', type=int, help="Peer's listening port")
    args = parser.parse_args()
    
    root = tk.Tk()
    app = SecureChatApp(root, args.user, args.my_port, args.peer_port)
    root.mainloop()