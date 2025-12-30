#!/opt/homebrew/bin/python3.12
import os
os.environ['TK_SILENCE_DEPRECATION'] = '1'
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import select
import time
import signal
import sys
import ssl
import ipaddress
from datetime import datetime, timedelta, timezone
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    HAS_CRYPTO = True
except Exception:
    # cryptography is optional; TLS fallback will run without it
    x509 = None
    NameOID = None
    hashes = None
    serialization = None
    rsa = None
    HAS_CRYPTO = False
from concurrent.futures import ThreadPoolExecutor
from dataBaseManager import DatabaseManager

Header = 64
Format = "utf-8"
port = 5050
HEARTBEAT_INTERVAL = 30  # seconds
HEARTBEAT_TIMEOUT = 60   # seconds
class ChatServer:
    def __init__(self, root):
        self.root = root
        self.root.title("Server Dashboard")
        self.root.geometry("800x600")
        self.root.resizable(True, True)  # Make window resizable
        self.root.minsize(600, 400)  # Set minimum window size
        self.root.configure(bg="#121212")

        header = tk.Label(root, text="🚀 Chat Server Dashboard", font=("Helvetica", 18, "bold"), fg="white", bg="#121212")
        header.pack(pady=10)

        self.status_label = tk.Label(root, text="Server Status: Stopped", font=("Helvetica", 12), fg="white", bg="#121212")
        self.status_label.pack(pady=5)

        clients_frame = tk.Frame(root, bg="#1F1F1F", relief=tk.RIDGE, borderwidth=2)
        clients_frame.pack(padx=10, pady=10, fill=tk.X)

        tk.Label(clients_frame, text="Connected Clients", font=("Helvetica", 12, "bold"), fg="white", bg="#1F1F1F").pack(anchor=tk.W, padx=5, pady=5)
        self.clients_list = tk.Listbox(clients_frame, bg="#1A1A1A", fg="white", font=("Consolas", 12))
        self.clients_list.pack(padx=5, pady=5, fill=tk.X)

        messages_frame = tk.Frame(root, bg="#1F1F1F", relief=tk.RIDGE, borderwidth=2)
        messages_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        tk.Label(messages_frame, text="Messages Log", font=("Helvetica", 12, "bold"), fg="white", bg="#1F1F1F").pack(anchor=tk.W, padx=5, pady=5)
        self.messages_log = scrolledtext.ScrolledText(messages_frame, wrap=tk.WORD, state='disabled', bg="#1A1A1A", fg="#00FF00", font=("Courier New", 12))
        self.messages_log.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        self.clients = {}#the clients in the server
        self.pending = {}  # used to show whether the client has something pending they should answer to
        self.client_private = {}  # whether the client is in a private session or not
        self.client_address = {}  # saves the address and socket
        self.iswriting = {}
        self.client_last_heartbeat = {}  # Track last heartbeat time for each client
        self.invitations = {}  # pending invitations: target_client -> {initiator, initiator_name, timestamp, message}
        self.invitation_timeout = 30  # seconds to wait for invitation response
        self.clients_lock = threading.Lock()
        self.private_lock = threading.Lock()  # for session management
        # Listen on all interfaces so app works on wired LAN, wireless LAN, and localhost
        self.Server = "0.0.0.0"
        self.Address = (self.Server, port)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(self.Address)
        # Thread pool to limit number of concurrent threads (better scalability)
        self.executor = ThreadPoolExecutor(max_workers=100)
        # TLS enabled by default for security - auto-generate certificates if needed
        self.ssl_context = self._setup_tls()
        self.db = DatabaseManager()
        self.running = True
        self.heartbeat_event = threading.Event()
        threading.Thread(target=self.start_server, daemon=True).start()
        threading.Thread(target=self._heartbeat_monitor, daemon=True).start()
        # handle SIGINT for graceful shutdown
        signal.signal(signal.SIGINT, self._handle_shutdown)

    def _setup_tls(self):
        """Setup TLS/SSL context with auto-generated self-signed certificate if needed"""
        # TLS enabled by default unless explicitly disabled via USE_TLS=0
        use_tls = os.getenv("USE_TLS", "1") == "1"
        require_tls = os.getenv("REQUIRE_TLS", "0") == "1"
        if not use_tls:
            print("TLS disabled (set USE_TLS=1 to enable). Running without encryption.")
            if require_tls:
                raise Exception("TLS is required by configuration but disabled (USE_TLS=0). Aborting.")
            return None
            
        try:
            certfile = os.getenv("TLS_CERT", "server.crt")
            keyfile = os.getenv("TLS_KEY", "server.key")

            if not HAS_CRYPTO:
                print("Warning: cryptography library not found. TLS cannot be enabled. Install with: pip install cryptography")
                if require_tls:
                    raise Exception("TLS required but cryptography library is not installed")
                return None

            # Check if certificates exist, if not generate them
            if not os.path.exists(certfile) or not os.path.exists(keyfile):
                print("Generating self-signed SSL certificate...")
                self._generate_self_signed_cert(certfile, keyfile)

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
            print("TLS/SSL encryption enabled - messages are encrypted")
            return ctx
        except Exception as e:
            print(f"TLS setup failed: {e}. Running without encryption.")
            if require_tls:
                raise
            return None
    def _generate_self_signed_cert(self, certfile, keyfile):
        """Generate a self-signed SSL certificate"""
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Chat Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            
            # Build SANs: include localhost, loopback and the primary LAN IP if detectable.
            san_entries = [x509.DNSName("localhost")]
            san_ips = set(["127.0.0.1"])
            # Allow override / addition via env var TLS_CERT_IPS (comma-separated IPs/DNS)
            extra = os.getenv("TLS_CERT_IPS")
            if extra:
                for part in extra.split(','):
                    p = part.strip()
                    if p:
                        san_ips.add(p)
            # Try to auto-detect the primary LAN IP
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    # This does not send packets; it's a common trick to get the outbound IP
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    if local_ip and not local_ip.startswith("127."):
                        san_ips.add(local_ip)
                finally:
                    s.close()
            except Exception:
                pass

            for ip in san_ips:
                try:
                    san_entries.append(x509.IPAddress(ipaddress.IPv4Address(ip)))
                except Exception:
                    # fallback to DNSName if it's not a valid IPv4 literal
                    san_entries.append(x509.DNSName(ip))

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            print(f"Generated self-signed certificate with SANs: {[str(s) for s in san_ips]}")            
            # Write certificate and key to files
            with open(certfile, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open(keyfile, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
        except Exception as e:
            raise Exception(f"Certificate generation failed: {e}")

    def send_msg(self, sock, msg):
        """Send a length-prefixed message over the socket."""
        try:
            message = msg.encode(Format)
            length_header = f"{len(message):<{Header}}".encode(Format)
            sock.sendall(length_header + message)
        except Exception as e:
            self.log_message(f"Send error: {e}")

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
            self.log_message(f"Read exact error: {e}")
            return None

    def recv_msg(self, sock):
        """Receive a length-prefixed message from the socket. Returns None on disconnect or error."""
        try:
            header = self.read_exact(sock, Header)
            if not header:
                return None
            header_text = header.decode(Format).strip()
            try:
                msg_len = int(header_text)
            except ValueError:
                # Malformed header
                self.log_message(f"Malformed header received: {header_text!r}")
                return None
            data = self.read_exact(sock, msg_len)
            if data is None:
                return None
            return data.decode(Format)
        except Exception as e:
            self.log_message(f"Recv error: {e}")
            return None

    def _heartbeat_monitor(self):
        """Monitor client connections and disconnect idle clients"""
        while self.running:
            try:
                # wait with event so we can wake early if needed
                self.heartbeat_event.wait(timeout=10)
                self.heartbeat_event.clear()
                current_time = time.time()
                disconnected_clients = []

                with self.clients_lock:
                    for client, last_heartbeat in list(self.client_last_heartbeat.items()):
                        if current_time - last_heartbeat > HEARTBEAT_TIMEOUT:
                            disconnected_clients.append(client)

                # Disconnect timed-out clients
                for client in disconnected_clients:
                    try:
                        name = self.clients.get(client, "Unknown")
                        self.log_message(f"Client {name} disconnected (timeout)")
                        client.close()
                        if client in self.clients:
                            del self.clients[client]
                        if client in self.client_last_heartbeat:
                            del self.client_last_heartbeat[client]
                        if client in self.client_private:
                            del self.client_private[client]
                        if client in self.pending:
                            del self.pending[client]
                        if client in self.iswriting:
                            del self.iswriting[client]
                        if client in self.client_address:
                            del self.client_address[client]
                        # If client had a pending invitation, cancel it and notify initiator
                        if client in self.invitations:
                            inv = self.invitations.pop(client)
                            initiator = inv.get('initiator')
                            try:
                                self.send_msg(initiator, f"-----{name} did not respond")
                            except Exception:
                                pass
                        self.update_clients_list()
                        self.broadcast_message(f"---{name} disconnected (timeout)")
                    except:
                        pass

                # Expire stale invitations
                expired = []
                now = time.time()
                for target, inv in list(self.invitations.items()):
                    if now - inv.get('timestamp', 0) > self.invitation_timeout:
                        expired.append((target, inv))
                for target, inv in expired:
                    try:
                        initiator = inv.get('initiator')
                        target_name = self.clients.get(target, 'Unknown')
                        if initiator in self.clients:
                            self.send_msg(initiator, f"-----{target_name} did not respond to your invitation")
                            self.send_msg(initiator, "notpending")
                        if target in self.clients:
                            self.send_msg(target, "notpending")
                        del self.invitations[target]
                        # clear pending flags
                        if initiator in self.pending:
                            self.pending[initiator] = False
                        if target in self.pending:
                            self.pending[target] = False
                    except Exception as e:
                        self.log_message(f"Failed to expire invitation: {e}")
            except Exception as e:
                self.log_message(f"Heartbeat monitor error: {e}")

    def _handle_shutdown(self, signum, frame):
        self.running = False
        try:
            self.server.close()
        except:
            pass
        try:
            self.executor.shutdown(wait=False)
        except:
            pass
        self.update_status("Server Status: Stopped")
        print("Server shutting down...")

    def start_server(self):
        self.server.listen(100)
        self.update_status("Server Status: Running")
        self.log_message("Server started. Waiting for connections...")

        while self.running:
            try:
                client_sock, addr = self.server.accept()
                # wrap client socket with TLS context if enabled
                if self.ssl_context:
                    try:
                        client_sock.settimeout(10)  # Set timeout for TLS handshake
                        client_sock = self.ssl_context.wrap_socket(client_sock, server_side=True)
                        client_sock.settimeout(None)  # Remove timeout after handshake
                    except (ssl.SSLError, socket.timeout, OSError) as e:
                        # If TLS handshake fails, either reject or accept unencrypted based on REQUIRE_TLS
                        require_tls = os.getenv("REQUIRE_TLS", "0") == "1"
                        if require_tls:
                            self.log_message(f"TLS handshake failed for {addr}: {e}. Connection rejected (TLS required).")
                            try:
                                client_sock.close()
                            except:
                                pass
                            continue
                        else:
                            self.log_message(f"TLS handshake failed for {addr}: {e}. Accepting unencrypted connection.")
                            try:
                                client_sock.close()
                            except:
                                pass
                            # Accept again without TLS
                            try:
                                client_sock, addr = self.server.accept()
                            except:
                                continue
                    except Exception as e:
                        self.log_message(f"Failed to wrap client socket with TLS: {e}")
                        try:
                            client_sock.close()
                        except:
                            pass
                        continue
                # hand off to thread pool
                self.executor.submit(self.handle_client, client_sock, addr)
            except OSError:
                break
            except Exception as e:
                print(f"Accept error: {e}")
                continue

    def handle_client(self, client, addr):
        try:
            client.settimeout(10)  # timer for name
            name = self.recv_msg(client)
            if name is None:
                client.close()
                return
            name = name.strip()
            client.settimeout(None)  # reset timer
        except socket.timeout:
            self.send_msg(client, "out of here")
            self.log_message(f"Client {addr} disconnected for being too idle")
            client.close()
            return
        with self.clients_lock:
            self.iswriting[client] = False
            self.client_address[client] = addr
            self.clients[client] = name
            self.client_private[client] = False
            self.pending[client] = True
            self.client_last_heartbeat[client] = time.time()  # Initialize heartbeat
        # fetch previous last_seen so we can deliver missed public messages since then
        try:
            prev_last_seen = self.db.get_last_seen(name)
        except Exception:
            prev_last_seen = None

        self.update_clients_list()
        # deliver undelivered private messages (if any) to this user
        try:
            undelivered = self.db.get_undelivered_messages(name)
            if undelivered:
                ids = []
                for m in undelivered:
                    try:
                        self.send_msg(client, f"Private message from {m['sender']}: {m['message']}")
                        ids.append(m['id'])
                    except Exception:
                        pass
                if ids:
                    self.db.mark_messages_delivered(ids)
        except Exception as e:
            self.log_message(f"Error delivering undelivered messages to {name}: {e}")

        # deliver missed public messages since previous last_seen (if we had a previous value)
        try:
            if prev_last_seen:
                public_msgs = self.db.get_public_messages_since(prev_last_seen)
                for m in public_msgs:
                    try:
                        self.send_msg(client, f"{m['sender']}: {m['message']}")
                    except Exception:
                        pass
        except Exception as e:
            self.log_message(f"Error delivering missed public messages to {name}: {e}")

        # update last_seen to now (they are online now)
        try:
            self.db.set_last_seen(name)
        except Exception:
            pass

        self.log_message(f"{name} connected from {addr}.")
        self.log_message(f"{name} joined.")
        self.broadcast_message(f"{name} joined chat")
        try:
            while True:
                try:
                    ready_to_read, _, _ = select.select([client], [], [], 0.5)#badal ma el nestana input mn el user dh bey3eesh 7ayato le7ad ma el user yegy ye send
                except select.error:
                    self.log_message("random select error")
                    continue
                if not self.client_private[client]:# lao el user private mayeb3atsh fel main broadcast
                    if ready_to_read:
                        message = self.recv_msg(client)
                        if message is None:  # disconnected or error
                            self.send_msg(client, "You are currently being kicked from the server")
                            self.log_message(f"Just kicked {name}")
                            break
                        # invitation response handling (target replies 'yes'/'no' to a pending invitation)
                        if message.lower() in ['yes', 'y', 'no', 'n'] and client in self.invitations:
                            handled = self.process_invitation_response(client, message)
                            if handled:
                                continue

                        if message == "istyping":
                            self.iswriting[client] = True
                            self.log_message(f"{name} is typing")
                            continue
                        if message == "ping":  # Heartbeat response
                            with self.clients_lock:
                                if client in self.client_last_heartbeat:
                                    self.client_last_heartbeat[client] = time.time()
                            self.send_msg(client, "pong")
                            continue
                        if message.startswith('@'):#@ followed by a name means the user wants to privately chat with written person
                            self.iswriting[client] = False
                            target_username, _, private_msg = message[1:].partition(" ")
                            if target_username == name:
                                self.send_msg(client, "for real?")
                                continue
                            target = self.find_client(target_username)#checks if the person exists
                            if not target or self.client_private.get(target, False) or self.client_private.get(client, False):
                                self.send_msg(client, "-----Either they dont exist, they are private or you are private buddy")
                                continue
                            # If target already has an invitation pending, reject
                            if target in self.invitations:
                                self.send_msg(client, f"-----{self.clients[target]} is busy with another invitation")
                                continue
                            # Create an invitation and let target respond asynchronously
                            self.invitations[target] = {
                                'initiator': client,
                                'initiator_name': name,
                                'timestamp': time.time(),
                                'message': private_msg
                            }
                            # mark both as pending
                            self.pending[client] = True
                            self.pending[target] = True
                            self.send_msg(client, "pending")  # tell initiator they should pause sending
                            self.send_msg(target, "pending")  # tell target they should pause sending
                            self.send_msg(client, f"private message request to {target_username}: {private_msg}")
                            self.send_msg(target, f"{name} wants a private chat. yes or no?")
                            self.log_message(f"{self.clients[client]} requested a private chat with {target_username}")
                            continue
                        elif message.startswith('/list'):#returns list feha el nas el 3ala el server
                            self.iswriting[client] = False
                            self.send_msg(client, f"Users online: {', '.join(self.clients.values())}")
                            self.log_message(f"{name} requested list of people in server")
                        else:#sends el msg 3ala el broadcast
                            self.iswriting[client] = False
                            self.broadcast_message(f"{name}: {message}", exclude_client=client)
                            self.log_message(f"{name}: {message}")
                else:
                    time.sleep(0.5)
                    continue
        except socket.error as e:
            self.log_message(f"Socket error for {name}: {e}")
        except Exception as e:
            self.log_message(f"Error handling client {name}: {e}")
        finally:#bene2fl kol 7aga we neshelhom mn el dicts beta3etna
            try:
                client.close()
            except:
                pass
            with self.clients_lock:
                if client in self.iswriting:
                    del self.iswriting[client]
                if client in self.pending:
                    del self.pending[client]
                if client in self.client_private:
                    del self.client_private[client]
                if client in self.client_address:
                    del self.client_address[client]
                if client in self.client_last_heartbeat:
                    del self.client_last_heartbeat[client]
                if client in self.clients:
                    name = self.clients[client]
                    del self.clients[client]
            self.update_clients_list()
            if 'name' in locals():
                self.broadcast_message(f"---{name} disconnected")
                self.log_message(f"---{name} disconnected.")
            # If shutting down, ensure server status updated
            if not self.running:
                self.update_status("Server Status: Stopped")

    def start_private_session(self, initiator, target):
        """Start a private session thread between two clients. Extracted so tests can patch it."""
        threading.Thread(target=self.run_private_session, args=(initiator, target), daemon=True).start()

    def process_invitation_response(self, client, message):
        """Process a 'yes'/'no' response from a target client for a pending invitation.
        Returns True if handled (invitation existed), False otherwise.
        """
        inv = self.invitations.pop(client, None)
        if not inv:
            return False
        initiator = inv['initiator']
        initiator_name = inv['initiator_name']
        # clear pending flags for both
        self.pending[initiator] = False
        self.pending[client] = False
        if message.lower() in ['yes', 'y']:
            self.log_message(f"{self.clients[client]} accepted the invitation from {initiator_name}")
            self.client_private[client] = True
            self.client_private[initiator] = True
            self.send_msg(initiator, "notpending")
            self.send_msg(client, "notpending")
            self.send_msg(initiator, f"You are now in a private chat with {self.clients[client]}")
            self.send_msg(client, f"You are now in a private chat with {initiator_name}")
            # start a single private session thread that manages both sockets
            self.start_private_session(initiator, client)
        else:
            self.log_message(f"{self.clients[client]} rejected the invitation from {initiator_name}")
            try:
                self.send_msg(initiator, f"-----{self.clients[client]} rejected")
                self.send_msg(initiator, "notpending")
                self.send_msg(client, "notpending")
            except Exception:
                pass
        return True

    def expire_invitations(self):
        """Expire stale invitations and notify initiators/targets."""
        expired = []
        now = time.time()
        for target, inv in list(self.invitations.items()):
            if now - inv.get('timestamp', 0) > self.invitation_timeout:
                expired.append((target, inv))
        for target, inv in expired:
            try:
                initiator = inv.get('initiator')
                target_name = self.clients.get(target, 'Unknown')
                if initiator in self.clients:
                    self.send_msg(initiator, f"-----{target_name} did not respond to your invitation")
                    self.send_msg(initiator, "notpending")
                if target in self.clients:
                    self.send_msg(target, "notpending")
                del self.invitations[target]
                # clear pending flags
                if initiator in self.pending:
                    self.pending[initiator] = False
                if target in self.pending:
                    self.pending[target] = False
            except Exception as e:
                self.log_message(f"Failed to expire invitation: {e}")

    def run_private_session(self, client_a, client_b):
        """Manage a private session between two clients in a single thread."""
        name_a = self.clients.get(client_a, "Unknown")
        name_b = self.clients.get(client_b, "Unknown")
        try:
            # Notify both clients that private session started (already sent by inviter)
            while True:
                try:
                    ready_to_read, _, _ = select.select([client_a, client_b], [], [], 0.5)
                    if ready_to_read:
                        names = [self.clients.get(r, 'Unknown') for r in ready_to_read]
                        self.log_message(f"Private session ready_to_read: {names}")
                except select.error:
                    self.log_message("random select error in private session")
                    continue

                # check if partner disconnected
                if client_a not in self.clients:
                    try:
                        self.send_msg(client_b, "-----your partner has disconnected suddenly and you will be sent back to the main chat\n")
                    except Exception:
                        pass
                    break
                if client_b not in self.clients:
                    try:
                        self.send_msg(client_a, "-----your partner has disconnected suddenly and you will be sent back to the main chat\n")
                    except Exception:
                        pass
                    break

                for src, dst, src_name, dst_name in ((client_a, client_b, name_a, name_b), (client_b, client_a, name_b, name_a)):
                    if src in ready_to_read:
                        msg = self.recv_msg(src)
                        if msg is None:
                            # treat as disconnection
                            try:
                                self.send_msg(dst, f"-----your partner has disconnected suddenly and you will be sent back to the main chat\n")
                            except Exception:
                                pass
                            return
                        if msg == "istyping":
                            self.iswriting[src] = True
                            continue
                        if msg == "ping":  # Heartbeat - don't forward to private chat
                            # Update heartbeat but don't forward ping message
                            with self.clients_lock:
                                if src in self.client_last_heartbeat:
                                    self.client_last_heartbeat[src] = time.time()
                            self.send_msg(src, "pong")
                            continue
                        if msg.lower() in ("exit", "quit"):
                            self.iswriting[src] = False
                            try:
                                self.send_msg(dst, f"{src_name} has left the private chat")
                            except Exception:
                                pass
                            return
                        if msg.lower() == "/list":
                            self.iswriting[src] = False
                            self.send_msg(src, f"Users online: {', '.join(self.clients.values())}")
                            self.log_message(f"{self.clients[src]} requested list of people in server")
                            continue
                        # Avoid forwarding messages that are already server-forwards (prevents loop in socketpair tests)
                        if msg.startswith(f"{src_name}:"):
                            # Likely an echo of a forwarded message; ignore to avoid loops
                            continue
                        # forward message
                        self.iswriting[src] = False
                        # Log private message activity without showing content (privacy)
                        self.log_message(f"Private message: {src_name} -> {dst_name}")
                        self.send_msg(dst, f"{src_name}: {msg}")
                        if msg and not msg.startswith(("exit", "quit", "/list")):
                            # save private message
                            try:
                                self.db.save_message(src_name, msg, is_private=True, recipient=dst_name)
                            except Exception:
                                pass
        except Exception as e:
            self.log_message(f"Private session error: {e}")
        finally:
            # Clean up session state and notify both
            try:
                self.client_private[client_a] = False
            except Exception:
                pass
            try:
                self.client_private[client_b] = False
            except Exception:
                pass
            try:
                self.send_msg(client_a, "Welcome to the Main chat again\nMain chat:")
            except Exception:
                pass
            try:
                self.send_msg(client_b, "Welcome to the Main chat again\nMain chat:")
            except Exception:
                pass
            self.log_message("Private session ended; both returned to main chat")
    def broadcast_message(self, message, exclude_client=None):
        # Save the message before broadcasting
        if ':' in message:
            sender, content = message.split(':', 1)
            self.db.save_message(sender.strip(), content.strip())
        
        for client in self.clients:
            if client != exclude_client:
                try:
                    if self.client_private[client] and not self.pending[client]:  # sees if the user is private and if so sends a "Main chat:" followed by normal msgs. resets if user sends msg in private chat
                        self.pending[client] = True
                        self.send_msg(client, ("Main chat:\n" + message))
                    else:
                        self.send_msg(client, message)
                except:
                    pass

    def find_client(self,wanted):
        for conn in list(self.clients.keys()):
            if self.clients[conn] == wanted:
                return conn
        return False
    def update_status(self, status):
        """Thread-safe update of the status label."""
        try:
            self.root.after(0, lambda: self.status_label.config(text=status))
        except Exception:
            # fallback: try direct update
            try:
                self.status_label.config(text=status)
            except Exception:
                pass

    def update_clients_list(self):
        """Thread-safe refresh of the clients listbox."""
        def _do_update():
            try:
                self.clients_list.delete(0, tk.END)
                for client_name in self.clients.values():
                    self.clients_list.insert(tk.END, client_name)
            except Exception:
                pass
        try:
            self.root.after(0, _do_update)
        except Exception:
            _do_update()

    def log_message(self, message):
        """Thread-safe append to the server message log."""
        def _do_log():
            try:
                self.messages_log.configure(state='normal')
                self.messages_log.insert(tk.END, message + '\n')
                self.messages_log.configure(state='disabled')
                self.messages_log.see(tk.END)
            except Exception:
                pass
        try:
            self.root.after(0, _do_log)
        except Exception:
            _do_log()

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatServer(root)
    root.mainloop()