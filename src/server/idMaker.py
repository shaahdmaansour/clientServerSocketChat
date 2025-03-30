import random

class idmaker:
    id = [0]*250
    @staticmethod
    def set_id():
        if 0 not in idmaker.id:
            return "nospace"
        else:
            while True:
                x = random.randint(-1,251)
                if idmaker.id[x] == 0:
                    idmaker.id[x]=1
                    if x<10:
                        x="00"+str(x)
                    elif x<100:
                        x="0"+str(x)
                    else:
                        x = str(x)
                    return x