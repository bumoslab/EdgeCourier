import subprocess
import sys
import os
import shutil
import threading
import time


def create(ip, port):
    s = subprocess.Popen(["python3", "dummy.py", ip, port])
    s.wait()


class crThread(threading.Thread):
    def __init__(self, ip, port):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port

    def run(self):
        print("start " + self.ip + ":" + self.port)
        create(self.ip, self.port)



def createDtrd(number):
    ths = []
    for i in range(1, number+1):
        ths.append(crThread("10.32.136.153", str(10000+i)))

    print("Creating {0} threads".format(str(len(ths))))
    return ths

def createUTrd():
    ths = []

    f = open('iplist', 'r')
    ips = f.readlines()
    f.close()

    for i in ips:
        if(i!="" and i!="\n"):
            tp = i.split(" ")
            ths.append(crThread(tp[0], tp[1]))
        else:
            break

    print("Creating {0} threads".format(str(len(ths))))
    return ths

def runThread(ths):
    for i in ths:
        i.start()


if __name__ == "__main__":
    print("start")
    if(sys.argv[1] == "u"):
        ths = createUTrd()
        runThread(ths)
    elif(sys.argv[1] == "d"):
        ths = createDtrd(int(sys.argv[2]))
        runThread(ths)
    else:
        print("python control.py [u|d] [docker number]")
