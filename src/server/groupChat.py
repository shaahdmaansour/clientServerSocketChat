from idmaker import idmaker

class groupchat:
    def __init__(self,name,client):
        self.id = idmaker.set_id()
        self.users = [client]
        self.name=name
        def adduser(self,socket):
            if len(self.users) == 50:
                return "MaximumCapacity"
            self.users.append(socket)
            return "succesful"
        def deleteuser(self,socket):
            if socket not in self.user:
                return "UserNotHere"
            else:
                for i in self.users:
                    if i == socket:
                        self.users.remove(i)
                        return "succesful"