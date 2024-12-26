import tkinter as tk
from tkinter import scrolledtext, messagebox
from socket import socket, gethostname, AF_INET, SOCK_STREAM
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES, DES, Blowfish
from diffiehellman.diffiehellman import DiffieHellman

HOST = gethostname()
PORT = 4600
SUPPORTED_CIPHERS = {"AES": [128, 192, 256],
                     "Blowfish": [112, 224, 448], "DES": [56]}

def generate_cipher_proposal(supported: dict) -> str:
    out = "ProposedCiphers:"
    out += ','.join([cipher + ':[' + ','.join([str(x) for x in bits]) + "]"
                     for cipher, bits in supported.items()])
    return out

def parse_cipher_selection(msg: str):
    msg_list = msg.split(':')[1].split(',')
    cipher_name = msg_list[0]
    key_size = int(msg_list[1])
    return cipher_name, key_size

def generate_dhm_request(public_key: int) -> str:
    return "DHMKE:" + str(public_key)

def parse_dhm_response(msg: str) -> int:
    return int(msg.split(':')[1])

def get_key_and_iv(shared_key: str, cipher_name: str, key_size: int):
    cipher_map = {"DES": DES, "AES": AES, "Blowfish": Blowfish}
    ivlen = {"DES": 8, "AES": 16, "Blowfish": 8}
    cipher = cipher_map.get(cipher_name)
    key = shared_key[:key_size // 8].encode()
    if cipher_name == "DES":
        key += b'\0'
    iv = shared_key[-1 * ivlen.get(cipher_name):].encode()
    return cipher, key, iv

def add_padding(message: str) -> bytes:
    padding = len(message)
    while padding % 16 != 0:
        padding += 1
    padding -= len(message)
    padded_message = message + '\0' * padding
    return padded_message.encode()

def encrypt_message(message: str, crypto: object, hashing: object):
    message = add_padding(message)
    ciphertext = crypto.encrypt(message)
    hashing.update(ciphertext)
    hashvalue = hashing.hexdigest()
    return ciphertext, hashvalue

class VPNClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VPN Client")
        self.root.geometry("600x400")

        self.client_sckt = None
        self.crypto = None
        self.hashing = None

        # UI Components
        self.server_frame = tk.Frame(root)
        self.server_frame.pack(pady=10)

        tk.Label(self.server_frame, text="Host:").pack(side=tk.LEFT)
        self.host_entry = tk.Entry(self.server_frame, width=20)
        self.host_entry.insert(0, HOST)
        self.host_entry.pack(side=tk.LEFT, padx=5)

        tk.Label(self.server_frame, text="Port:").pack(side=tk.LEFT)
        self.port_entry = tk.Entry(self.server_frame, width=10)
        self.port_entry.insert(0, str(PORT))
        self.port_entry.pack(side=tk.LEFT, padx=5)

        self.connect_button = tk.Button(self.server_frame, text="Connect", command=self.connect_to_server)
        self.connect_button.pack(side=tk.LEFT, padx=5)

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=15, width=70)
        self.text_area.pack(pady=10)
        self.text_area.insert(tk.END, "Disconnected. Connect to a server.\n")

        self.input_frame = tk.Frame(root)
        self.input_frame.pack(pady=10)

        self.message_entry = tk.Entry(self.input_frame, width=50)
        self.message_entry.pack(side=tk.LEFT, padx=5)

        self.send_button = tk.Button(self.input_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=5)

    def connect_to_server(self):
        try:
            self.client_sckt = socket(AF_INET, SOCK_STREAM)
            self.client_sckt.connect((self.host_entry.get(), int(self.port_entry.get())))
            self.text_area.insert(tk.END, f"Connected to {HOST}:{PORT}\n")

            # Negotiating the cipher
            self.text_area.insert(tk.END, "Negotiating the cipher...\n")
            msg_out = generate_cipher_proposal(SUPPORTED_CIPHERS)
            self.client_sckt.send(msg_out.encode())
            msg_in = self.client_sckt.recv(4096).decode('utf-8')
            cipher_name, key_size = parse_cipher_selection(msg_in)
            self.text_area.insert(tk.END, f"Using cipher: {cipher_name} {key_size}\n")

            # Negotiating the key
            self.text_area.insert(tk.END, "Negotiating the key...\n")
            dh = DiffieHellman()
            dh.generate_public_key()
            msg_out = generate_dhm_request(dh.public_key)
            self.client_sckt.send(msg_out.encode())
            msg_in = self.client_sckt.recv(4096).decode('utf-8')
            server_public_key = parse_dhm_response(msg_in)
            dh.generate_shared_secret(server_public_key)
            cipher, key, iv = get_key_and_iv(dh.shared_key, cipher_name, key_size)

            # Initialize Cryptosystem
            self.crypto = cipher.new(key, cipher.MODE_CBC, iv)
            self.hashing = HMAC.new(key, digestmod=SHA256)
            self.text_area.insert(tk.END, "Connection established. All systems ready.\n")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect: {str(e)}")

    def send_message(self):
        try:
            msg = self.message_entry.get()
            if not msg:
                return

            if msg == "\\quit":
                self.client_sckt.close()
                self.text_area.insert(tk.END, "Disconnected.\n")
                return

            ciph_out, hmac_out = encrypt_message(msg, self.crypto, self.hashing)
            self.client_sckt.send(ciph_out + hmac_out.encode())
            msg_in = self.client_sckt.recv(4096).decode("utf-8")
            self.text_area.insert(tk.END, f"Server: {msg_in}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = VPNClientApp(root)
    root.mainloop()
