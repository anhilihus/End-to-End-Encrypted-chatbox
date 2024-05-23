import socket
import threading
import rsa
import tkinter as tk
from tkinter import ttk

pubkey, privkey = rsa.newkeys(1024)
pubpart = None
client = None

def start_server():
    global pubpart, client
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("192.168.37.26", 29)) #insert the ip addr of your pc
    server.listen()
    client, _ = server.accept()
    client.send(pubkey.save_pkcs1("PEM"))
    pubpart = rsa.PublicKey.load_pkcs1(client.recv(1024))
    start_chat()

def start_client():
    global pubpart, client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("192.168.37.26", 29)) #insert the ip addr of your pc
    pubpart = rsa.PublicKey.load_pkcs1(client.recv(1024))
    client.send(pubkey.save_pkcs1("PEM"))
    start_chat()

def send_message(message_entry):
    message = message_entry.get()
    client.send(rsa.encrypt(message.encode(), pubpart))
    message_entry.delete(0, tk.END)
    chat_box.config(state=tk.NORMAL)
    chat_box.insert(tk.END, "You: " + message + "\n")
    chat_box.config(state=tk.DISABLED)

def receive_message():
    while True:
        message = rsa.decrypt(client.recv(1024), privkey).decode()
        chat_box.config(state=tk.NORMAL)
        chat_box.insert(tk.END, "Them: " + message + "\n")
        chat_box.config(state=tk.DISABLED)

def start_chat():
    threading.Thread(target=receive_message).start()

root = tk.Tk()
root.title("EncryptedChat")

root.configure(bg="black")

style = ttk.Style()
style.theme_use("vista")

frame = tk.Frame(root, padx=10, pady=10, bg="black")
frame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))
frame.columnconfigure(0, weight=1)  
frame.rowconfigure(6, weight=1)    

start_server_button = ttk.Button(frame, text="Host (1)", command=start_server)
start_server_button.grid(row=0, column=0, padx=10, pady=5, sticky="ew")

start_client_button = ttk.Button(frame, text="Connect (2)", command=start_client)
start_client_button.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

message_label = tk.Label(frame, text="Message:", bg="black", fg="white")
message_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")

message_entry = ttk.Entry(frame)
message_entry.grid(row=3, column=0, padx=10, pady=5, sticky="ew")
message_entry.bind("<Return>", lambda event=None: send_message(message_entry)) 

send_button = ttk.Button(frame, text="Send", command=lambda: send_message(message_entry))
send_button.grid(row=4, column=0, padx=10, pady=5, sticky="ew")

chat_box = tk.Text(frame, height=15, width=40, state=tk.DISABLED, bg="black", fg="white")
chat_box.grid(row=5, column=0, padx=10, pady=5, sticky="ew")

root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

root.mainloop()
