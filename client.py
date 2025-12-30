#!/opt/homebrew/bin/python3.12
import os
os.environ['TK_SILENCE_DEPRECATION'] = '1'
import socket
import ssl
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
HEARTBEAT_INTERVAL = 30  # seconds
iswriting = False
class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Application")
        self.root.geometry("800x600")
        self.root.resizable(True, True)  # Make window resizable
        self.root.minsize(600, 400)  # Set minimum window size
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
        # bind Enter -> send_message (send_message accepts an optional event now)
        self.entry.bind('<Return>', self.send_message)
        # typing indicator via keypress events (avoid polling)
        self.entry.bind('<KeyPress>', self._on_keypress)

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
        self.iswriting = False
        self.server_ip = None
        self.client_name = None
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 5
        self.connect_to_server()

    def _safe_show_error(self, title, message):
        """Show an error messagebox in a thread-safe manner."""
        try:
            self.root.after(0, lambda: messagebox.showerror(title, message))
        except Exception:
            try:
                messagebox.showerror(title, message)
            except Exception:
                pass

    def _safe_quit(self):
        """Quit the application from any thread safely."""
        try:
            self.root.after(0, self.root.quit)
        except Exception:
            try:
                self.root.quit()
            except Exception:
                pass

    def connect_to_server(self, reconnect=False):
        try:
            if not reconnect:
                server_input = askstring("Server IP", "Enter server IP (leave empty for localhost):")
                self.server_ip = server_input.strip() if server_input else '127.0.0.1'
            else:
                self.display_message("Attempting to reconnect...")
            
            self.Server = self.server_ip
            self.Address = (self.Server, port)
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.settimeout(10)  # Connection timeout
            
            # TLS is enabled by default unless USE_TLS=0
            use_tls = os.getenv("USE_TLS", "1") == "1"
            require_tls = os.getenv("REQUIRE_TLS", "0") == "1"

            if use_tls:
                try:
                    import ssl
                    # Create SSL context for TLS connection
                    # Accept self-signed certificates by default (for auto-generated certs)
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                    # Wrap socket BEFORE connecting for proper TLS handshake
                    self.client = ctx.wrap_socket(self.client, server_hostname=self.Server)
                    self.client.settimeout(10)
                    self.client.connect(self.Address)
                    self.display_message("✓ Connected with encryption (TLS/SSL)")
                except ImportError:
                    if require_tls:
                        self._safe_show_error("TLS Error", "cryptography/ssl is required but not available. Cannot establish a secure connection.")
                        self._safe_quit()
                        return
                    use_tls = False
                    self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.client.settimeout(10)
                    self.client.connect(self.Address)
                    self.display_message("⚠ Warning: SSL not available, connection unencrypted")
                except Exception as e:
                    # TLS failed
                    if require_tls:
                        self._safe_show_error("TLS Error", f"TLS connection failed and is required: {e}")
                        self._safe_quit()
                        return
                    use_tls = False
                    try:
                        self.client.close()
                    except:
                        pass
                    self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.client.settimeout(10)
                    self.client.connect(self.Address)
                    self.display_message("⚠ TLS failed, connected without encryption")
            else:
                # Connect without TLS
                self.client.connect(self.Address)
                self.display_message("✓ Connected to server")
            
            if not reconnect:
                name = askstring("Enter Name", "Please enter your name:")
                if not name:
                    self._safe_quit()
                    return
                self.client_name = name
            else:
                name = self.client_name
            
            # Update window title to show client name
            self.root.title(f"Chat Application - {name}")
            
            self.client.settimeout(None)  # Remove timeout after connection
            self.send_msg(self.client, name)
            chat_history = self.db.get_chat_history(name)
            for msg in reversed(chat_history):
                self.display_message(f"{msg['sender']}: {msg['message']}")

            self.connected = True
            self.reconnect_attempts = 0
            threading.Thread(target=self.receive_messages, args=(), daemon=True).start()
            # typing is handled by key events (no polling thread)
            threading.Thread(target=self._heartbeat_sender, args=(), daemon=True).start()
        except socket.timeout:
            if reconnect and self.reconnect_attempts < self.max_reconnect_attempts:
                self.reconnect_attempts += 1
                time.sleep(2)
                self.connect_to_server(reconnect=True)
            else:
                self._safe_show_error("Connection Error", "Connection timeout. Server may be unreachable.")
                if not reconnect:
                    self._safe_quit()
        except Exception as e:
            if reconnect and self.reconnect_attempts < self.max_reconnect_attempts:
                self.reconnect_attempts += 1
                time.sleep(2)
                self.connect_to_server(reconnect=True)
            else:
                self._safe_show_error("Connection Error", f"Unable to connect to server: {e}")
                if not reconnect:
                    self._safe_quit()

    def send_msg(self, sock, msg):
        """Send a length-prefixed message."""
        try:
            message = msg.encode(Format)
            length_header = f"{len(message):<{Header}}".encode(Format)
            sock.sendall(length_header + message)
        except Exception as e:
            print(f"Send error: {e}")

    def read_exact(self, sock, n):
        """Read exactly n bytes from sock, or return None if disconnected."""
        data = b''
        try:
            while len(data) < n:
                packet = sock.recv(n - len(data))
                if not packet:
                    return None
                data += packet
            return data
        except Exception as e:
            print(f"Read exact error: {e}")
            return None

    def recv_msg(self, sock):
        """Receive a length-prefixed message. Returns None on disconnect or error."""
        try:
            header = self.read_exact(sock, Header)
            if not header:
                return None
            header_text = header.decode(Format).strip()
            try:
                msg_len = int(header_text)
            except ValueError:
                print(f"Malformed header received: {header_text!r}")
                return None
            data = self.read_exact(sock, msg_len)
            if data is None:
                return None
            return data.decode(Format)
        except Exception as e:
            print(f"Recv error: {e}")
            return None

    def receive_messages(self):
        while self.connected:
            try:
                msg = self.recv_msg(self.client)  # use length-prefixed recv
                if msg is None:
                    self._handle_disconnection()
                    break
                elif msg == "pending":  # lao el msg pending haybatal yeb3at en howa beyekteb wala l2 fe function iswriting
                    self.pending = True
                    continue
                elif msg == "notpending":  # haykamel yeb3at el status beta3to
                    self.pending = False
                    continue
                elif msg == "pong":  # Heartbeat response
                    continue
                print(f"Received message: {msg}")  # Debugging
                self.display_message(msg)
            except ssl.SSLError as e:
                # SSL errors - try to reconnect without TLS
                print(f"SSL error receiving message: {e}")
                self.display_message("⚠ SSL connection error. Reconnecting...")
                self._handle_disconnection()
                break
            except socket.error as e:
                print(f"Socket error receiving message: {e}")
                self._handle_disconnection()
                break
            except Exception as e:
                print(f"Error receiving message: {e}")  # Debugging
                self._handle_disconnection()
                break
    
    def _handle_disconnection(self):
        """Handle connection loss and attempt reconnection"""
        if not self.connected:
            return  # Already handling disconnection
            
        self.connected = False
        self.display_message("⚠ Connection lost. Attempting to reconnect...")
        try:
            self.client.close()
        except:
            pass
        
        # Attempt to reconnect
        if self.reconnect_attempts < self.max_reconnect_attempts:
            self.reconnect_attempts += 1
            time.sleep(2)
            try:
                self.connect_to_server(reconnect=True)
            except Exception as e:
                if self.reconnect_attempts >= self.max_reconnect_attempts:
                    self.display_message("❌ Failed to reconnect. Please restart the client.")
                    messagebox.showerror("Connection Lost", "Failed to reconnect to server. Please restart the application.")
        else:
            self.display_message("❌ Failed to reconnect. Please restart the client.")
            messagebox.showerror("Connection Lost", "Failed to reconnect to server. Please restart the application.")
    
    def _heartbeat_sender(self):
        """Send periodic heartbeat to server"""
        while self.connected:
            try:
                time.sleep(HEARTBEAT_INTERVAL)
                if self.connected and self.client:
                    self.send_msg(self.client, "ping")
            except Exception as e:
                if self.connected:
                    print(f"Heartbeat error: {e}")
                    self._handle_disconnection()
                break
    def iswriting_loop(self):
        # legacy: not used when event-driven typing is enabled
        while self.connected:
            time.sleep(1)

    def _on_keypress(self, event=None):
        try:
            if not self.iswriting and not self.pending:
                try:
                    self.send_msg(self.client, "istyping")
                except Exception:
                    pass
                self.iswriting = True
            # reset inactivity timer using tkinter after method
            if hasattr(self, 'typing_timer') and self.typing_timer is not None:
                try:
                    self.root.after_cancel(self.typing_timer)
                except Exception:
                    pass
            # set timer to clear typing after 2 seconds of inactivity
            self.typing_timer = self.root.after(2000, self._typing_timeout)
        except Exception as e:
            print(f"Keypress handler error: {e}")

    def _typing_timeout(self):
        self.iswriting = False
        self.typing_timer = None

    def send_message(self, event=None):
        # event param optional so binding with <Return> works
        msg = self.entry.get().strip()
        if msg:
            self.entry.delete(0, tk.END)
            try:
                if not self.connected or not self.client:
                    messagebox.showerror("Not connected", "Not connected to server.")
                    return
                print(f"Sent message: {msg}")  # Debugging
                if msg.lower() in ['disconnect', 'leave', 'bye']:
                    self.connected = False
                    try:
                        self.client.close()
                    except:
                        pass
                    self.root.quit()
                self.send_msg(self.client, msg)
                self.display_message(f"me: {msg}")
            except Exception as e:
                messagebox.showerror("Send Error", f"Error sending message: {e}")
                print(f"Send error: {e}")

    def display_message(self, msg):
        """Thread-safe display of a message in the chat area."""
        def _do_display():
            try:
                print(f"Displaying message in GUI: {msg}")  # Debugging
                self.chat_area.configure(state='normal')
                self.chat_area.insert(tk.END, msg + '\n')
                self.chat_area.configure(state='disabled')
                self.chat_area.see(tk.END)
            except Exception as e:
                print(f"Error displaying message: {e}")  # Debugging
        try:
            self.root.after(0, _do_display)
        except Exception:
            _do_display()

###
    def clear_history(self):
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to clear ALL chat history from the database? This cannot be undone."):
            # Clear the database completely first
            self.db.clear_chat_history()
            # Then clear the GUI display
            self.chat_area.configure(state='normal')
            self.chat_area.delete(1.0, tk.END)
            self.chat_area.configure(state='disabled')
            self.display_message("Chat history cleared from database.")
###

if __name__ == "__main__":
    root = tk.Tk()
    client_app = ChatClient(root)
    root.mainloop()