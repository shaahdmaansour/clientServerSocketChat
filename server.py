import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import select
import time
import traceback
from dataBaseManager import DatabaseManager
from groupchat import groupchat

Header = 64
Format = "utf-8"
port = 5050
class ChatServer:
    def __init__(self, root):
        self.root = root
        self.root.title("Server Dashboard")
        self.root.geometry("800x600")
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
        self.pending= {}#not used right now. used to show whether the client has something pending they should answer to
        self.client_private = {}#whether the client is private or not
        self.client_address = {}#saves the address and socket
        self.group_chats = {}
        self.iswriting = {}
        self.clients_lock = threading.Lock()#msh 3aref
        self.private_lock = threading.Lock()#msh 3aref
        self.Server = socket.gethostbyname(socket.gethostname())
        self.Address = (self.Server, port)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(self.Address)
        self.db = DatabaseManager()
        threading.Thread(target=self.start_server).start()

    def start_server(self):
        self.server.listen(100)
        self.update_status("Server Status: Running")
        self.log_message("Server started. Waiting for connections...")

        while True:
            client, addr = self.server.accept()
            threading.Thread(target=self.handle_client, args=(client, addr)).start()

    def handle_client(self, client, addr):
        try:
            client.settimeout(10)#timer lel esm
            name = client.recv(Header).decode(Format).strip()#el esm
            client.settimeout(None)#reset timer
        except socket.timeout:
            client.send("out of here".encode(Format))
            self.log_message(f"Client {addr} disconnected for being too idle")
            client.close()
            return
        with self.clients_lock:
            self.iswriting[client] = False
            self.client_address[client] = addr
            self.clients[client] = name
            self.client_private[client] = False
            self.pending[client] = True
        self.update_clients_list()
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
                        message = client.recv(Header).decode(Format)
                        if not message:# lao somehow ba3at 3abat fel msg
                            client.send("You are currently being kicked from the serve".encode(Format))
                            self.log_message(f"Just kicked {name}")
                            break
                        if message == "istyping":
                            self.iswriting[client] = True
                            self.log_message(f"{name} is typing")
                            continue
                        if message.startswith('@'):#@ followed by a name means the user wants to privately chat with written person
                            command,_,_ = message[1:].partition(" ")
                            command=command.lower()
                            self.log_message(f"{name} entered command "+command)
                            if command in ["private","p"]:
                                self.iswriting[client] = False
                                _, _, target_username = message[1:].partition(" ")
                                if target_username == name:
                                    client.send("for real?".encode(Format))
                                    continue
                                target = self.find_client(target_username)#checks if the person exists
                                if target and not self.client_private.get(target,False) and not self.client_private.get(client,False):#if they exist and the client and target not private if is true
                                    client.send("pending".encode(Format))#makes them pending to stop them from sending whether they are writing or not
                                    target.send("pending".encode(Format))#makes them pending to stop them from sending whether they are writing or not
                                    client.send(f"private message request to {target_username}".encode(Format))#tamhedat
                                    target.send(f"{name} wants a private chat. yes or no?".encode(Format))#tamhedat
                                    self.log_message(f"{self.clients[client]} requested a private chat with {target_username}")#debug
                                    try:
                                        ready_to_read, _, _ = select.select([target], [], [], 0.5)
                                        target.settimeout(10)
                                        response = target.recv(Header).decode(Format).lower()
                                        target.settimeout(None)
                                    except socket.timeout:
                                        target.settimeout(None)
                                        client.send("No buddy answered buddy".encode(Format))
                                        continue
                                    if response in ['yes', 'y']:
                                        self.log_message(f"{target_username} accepted the invitation")
                                        self.client_private[target] = True#delwa2ty homa private
                                        self.client_private[client] = True#delwa2ty homa private
                                        client.send("notpending".encode(Format))#makes them resume the process of sending whether they are writing or not
                                        target.send("notpending".encode(Format))#makes them resume the process of sending whether they are writing or not
                                        client.send(f"You are now in a private chat with {target_username}".encode(Format))
                                        target.send(f"You are now in a private chat with {name}".encode(Format))
                                        threading.Thread(target=self.private_chat, args=(client, target)).start()#threads to initiate private text chat
                                        threading.Thread(target=self.private_chat, args=(target, client)).start()#threads to initiate private text chat
                                    else:#buddy 7asalo reject or matradesh 3aleeh
                                        client.send(f"-----{self.clients[target]} rejected".encode(Format))
                                else:
                                    client.send("-----Either they dont exist, they are private or you are private buddy".encode(Format))
                                    continue
                            elif command in ["creatgroupchat","cgc"]:
                                try:
                                    _,_,Groupname = message[1:].partition(" ")
                                    newGroup = groupchat(Groupname,client)
                                    if newGroup.id == "nospace":
                                        client.send("There is no space for another group chat".encode(Format))
                                        continue
                                    client.send(("id="+newGroup.id).encode(Format))
                                    self.group_chats[newGroup.id] = newGroup
                                    self.log_message(f"A new groupchat {Groupname} has been created. There is a total of {len(self.group_chats)} now")
                                except Exception as e:
                                    client.send(traceback.format_exc().encode(Format))
                            else:
                                try:
                                    if int(command)>=0 and int(command)<=250:
                                        for i in self.group_chats.values():
                                            self.log_message(f"currently at {i.name}")
                                            if command == i.id:
                                                self.log_message(f"message sent to {i.name}")
                                                self.broadcast_message(f"{name}: {message[3:]}", exclude_client=client)
                                                raise Exception()
                                        client.send("The chat you entered is wrong".encode(Format))
                                        continue
                                except:
                                    self.log_message("3adena mn hena")
                                    continue
                                client.send("wrong usage of command '@'".encode(Format))
                        elif message.startswith('/list'):#returns list feha el nas el 3ala el server
                            self.iswriting[client] = False
                            client.send(f"Users online: {', '.join(self.clients.values())}".encode(Format))
                            self.log_message(f"{name} requested list of people in server")
                        else:#sends el msg 3ala el broadcast
                            self.iswriting[client] = False
                            self.broadcast_message(f"{name}: {message}", exclude_client=client)
                            self.log_message(f"{name}: {message}")
                else:
                    time.sleep(0.5)
                    continue
        except Exception as e:
            client.send(traceback.format_exc().encode(Format))
 
        finally:#bene2fl kol 7aga we neshelhom mn el dicts beta3etna
            client.close()
            del self.iswriting[client]
            del self.pending[client]
            del self.client_private[client]
            del self.client_address[client]
            del self.clients[client]
            self.update_clients_list()
            self.broadcast_message(f"---{name} disconnected")
            self.log_message(f"---{name} disconnected.")

    def private_chat(self,client,target):
        try:
            while True:
                try:
                    ready_to_read, _, _ = select.select([client], [], [],0.5)  # badal ma el nestana input mn el user dh bey3eesh 7ayato le7ad ma el user yegy ye send
                except select.error:
                    self.log_message("random select error")
                    continue
                if target not in self.clients.keys():
                    client.send("-----your partner has disconnected suddenly and you will be sent back to the main chat\n".encode(Format))
                    return
                elif not self.client_private[target]:
                    return
                elif self.pending[client] and (self.iswriting[target] or self.iswriting[client]):#checks a5er msg kanet mn el main wala private. for reference enzl le broadcast function
                    self.pending[client] = False
                    client.send("Private chat:".encode(Format))
                if ready_to_read:
                    msg = client.recv(Header).decode(Format)
                    if msg == "istyping":#lao galo is typing 3alashan el user badal ma hayeb3atha lel server hayeb3atha hena
                        self.iswriting[client] = True
                        continue#shoof 3ayzeen te implement eh hena. momken 7aga foo2 el chat te3arafo meen beyektb
                    if msg.lower() == "exit" or msg.lower() == "quit":#lao 3ayz yetl3 bara el private chat we yerg3 el main chat
                        self.iswriting[client] = False
                        if self.client_private[client] and self.client_private[target]:# checks whether the other person left too or not
                            target.send(f"{self.clients[client]} has left the private chat".encode(Format))
                            return
                        else:
                            return
                    elif msg.lower() == "/list":#lao 3ayz el list
                        self.iswriting[client] = False
                        client.send(f"Users online: {', '.join(self.clients.values())}".encode(Format))
                        self.log_message(f"{self.clients[client]} requested list of people in server")
                    else:
                        self.iswriting[client] = False
                        target.send(f"{self.clients[client]}: {msg}".encode(Format))
                        if msg and not msg.startswith(('exit', 'quit', '/list')):
                            self.db.save_message(
                                self.clients[client],
                                msg,
                                is_private=True,
                                recipient=self.clients[target]
                            )
        except Exception as e:
            print(f"Error happened and you exit to the main chat again: {e}")
            return

        finally:
            self.log_message("feeh wa7ed beyed5ol we yetl3 3alatool")
            client.send("Welcome to the Main chat again\nMain chat:".encode(Format))
            self.client_private[client] = False

    def broadcast_message(self, message, exclude_client=None):
        # Save the message before broadcasting
        if ':' in message:
            sender, content = message.split(':', 1)
            self.db.save_message(sender.strip(), content.strip())
        
        for client in self.clients:
            if client != exclude_client:
                try:
                    if self.client_private[client] and not self.pending[client]:#sees if the user is private and if so sends a "Main chat:" followed by normal msgs. resets if user sends msg in private chat
                        self.pending[client] = True#bos foo2 3al function private messaging for reference
                        client.send(("Main chat:\n"+message).encode(Format))
                    else:
                        client.send(message.encode(Format))
                except:
                    pass
    
    def group_chat(self,num):
        chat_id = num
        users = []

    def find_client(self,wanted):
        for conn in list(self.clients.keys()):
            if self.clients[conn] == wanted:
                return conn
        return False
    def update_status(self, status):
        self.status_label.config(text=status)

    def update_clients_list(self):
        self.clients_list.delete(0, tk.END)
        for client_name in self.clients.values():
            self.clients_list.insert(tk.END, client_name)

    def log_message(self, message):
        self.messages_log.configure(state='normal')
        self.messages_log.insert(tk.END, message + '\n')
        self.messages_log.configure(state='disabled')
        self.messages_log.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatServer(root)
    root.mainloop()