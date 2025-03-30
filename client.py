import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from tkinter.simpledialog import askstring
import time
from dataBaseManager import DatabaseManager

Header = 64
Disconnect = "!bye"
Format = "utf-8"
port = 5050
iswriting = False


class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Application")

        self.root.geometry("1200x800")
        self.root.configure(bg="#0F0F0F")

        header_frame = tk.Frame(root, bg="#1C1C1C", height=60)
        header_frame.pack(fill=tk.X)

        header_label = tk.Label(header_frame, text="🚀 Chat Application", font=("Helvetica", 22, "bold"), fg="white", bg="#1C1C1C")
        header_label.pack(pady=10)

        chat_frame = tk.Frame(root, bg="#0F0F0F")
        chat_frame.pack(padx=15, pady=10, fill=tk.BOTH, expand=True)

        self.chat_area = scrolledtext.ScrolledText(chat_frame, wrap=tk.WORD, state='disabled', bg="#1A1A1A", fg="#00FF00", font=("Courier New", 14), relief=tk.FLAT, borderwidth=5, highlightbackground="#FF5733", highlightthickness=2)
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        entry_frame = tk.Frame(root, bg="#0F0F0F")
        entry_frame.pack(fill=tk.X, pady=10)

        self.entry = tk.Entry(entry_frame, width=70, bg="#2E2E2E", fg="#FFFFFF", font=("Courier New", 14), relief=tk.FLAT, borderwidth=5, highlightbackground="#FF5733", highlightthickness=2)
        self.entry.pack(padx=10, pady=5, side=tk.LEFT, fill=tk.X, expand=True)
        self.entry.bind('<Return>', self.send_message)

###
        self.delete_button = tk.Button(entry_frame, text="Clear History", command=self.clear_history, 
                                     bg="#C70039", fg="white", font=("Helvetica", 12, "bold"), 
                                     relief=tk.RAISED, activebackground="#8B0000", 
                                     activeforeground="white", cursor="hand2")
        self.delete_button.pack(padx=10, pady=5, side=tk.RIGHT)
###

        self.send_button = tk.Button(entry_frame, text="Send", command=self.send_message, bg="#FF5733", fg="white", font=("Helvetica", 14, "bold"), relief=tk.RAISED, activebackground="#C70039", activeforeground="white", cursor="hand2")
        self.send_button.pack(padx=10, pady=5, side=tk.RIGHT)

        footer_frame = tk.Frame(root, bg="#1C1C1C", height=40)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)

        footer_label = tk.Label(footer_frame, text="© 2024 Chat App - All Rights Reserved", font=("Helvetica", 10), fg="white", bg="#1C1C1C")
        footer_label.pack(pady=5)

        self.db = DatabaseManager()
        self.client = None
        self.connected = False
        self.pending = False

        self.connect_to_server()

    def connect_to_server(self):
        try:
            self.Server = socket.gethostbyname(socket.gethostname())
            self.Address = (self.Server, port)
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.connect(self.Address)

            name = askstring("Enter Name", "Please enter your name:")
            if not name:
                self.root.quit()
                return
            self.client.send(name.encode(Format))
            chat_history = self.db.get_chat_history(name)
            for msg in reversed(chat_history):
                self.display_message(f"{msg['sender']}: {msg['message']}")

            self.connected = True
            threading.Thread(target=self.receive_messages, args=()).start()
            threading.Thread(target=self.iswriting, args=()).start()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Unable to connect to server: {e}")
            self.root.quit()

    def receive_messages(self):
        while self.connected:
            try:
                msg = self.client.recv(Header).decode(Format)  # Increased buffer size
                if not msg:
                    break
                elif msg == "pending":#lao el msg pending haybatal yeb3at en howa beyekteb wala l2 fe function iswriting
                    self.pending = True
                    continue
                elif msg == "notpending":#haykamel yeb3at el status beta3to
                    self.pending = False
                    continue
                print(f"Received message: {msg}")  # Debugging
                self.display_message(msg)
            except Exception as e:
                print(f"Error receiving message: {e}")  # Debugging
                self.display_message("Connection lost.")
                break
    def iswriting(self):
        while True:
            try:#kol 0.3 seconds beychek lao feeh 7aga maktoba fe el text box. lao feeh beyeb3at eno beyektb
                time.sleep(0.3)
                msg = self.entry.get()
                if msg == "":
                    iswriting=False
                    continue
                else:
                    if not iswriting and not self.pending:
                        self.client.send("istyping".encode(Format))
                        iswriting=True
            except Exception as e:
                self.display_message(f"{e}")

    def send_message(self):
        msg = self.entry.get().strip()
        if msg:
            self.entry.delete(0, tk.END)
            try:
                print(f"Sent message: {msg}")  # Debugging
                if msg.lower() in ['disconnect', 'leave', 'bye']:
                    self.connected = False
                    self.client.close()
                    self.root.quit()
                self.client.send(msg.encode(Format))
                self.display_message(f"me: {msg}")
            except Exception as e:
                messagebox.showerror("Send Error", f"Error sending message: {e}")

    def display_message(self, msg):
        try:
            print(f"Displaying message in GUI: {msg}")  # Debugging
            self.chat_area.configure(state='normal')
            self.chat_area.insert(tk.END, msg + '\n')
            self.chat_area.configure(state='disabled')
            self.chat_area.see(tk.END)
        except Exception as e:
            print(f"Error displaying message: {e}")  # Debugging

###
    def clear_history(self):
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to clear the chat history?"):
            self.chat_area.configure(state='normal')
            self.chat_area.delete(1.0, tk.END)
            self.chat_area.configure(state='disabled')
            # Clear the database history if you want to persist the deletion
            self.db.clear_chat_history()
###

if __name__ == "__main__":
    root = tk.Tk()
    client_app = ChatClient(root)
    root.mainloop()