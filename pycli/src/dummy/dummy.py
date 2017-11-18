import socket
import os
import shutil
import sys
import time
import cmp as diff



def createUser(ip, port, username):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    s.send(bytes("{'op':1, 'user':'"+username+"'}", 'utf-8').ljust(1000))
    s.close()

def registerFile(ip, port, username, filename, filepath):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    print("{'op':2, 'user':'"+username+"', 'filename':'"+filename+"'}")
    s.send(bytes("{'op':2, 'user':'"+username+"', 'filename':'"+filename+"'}", 'utf-8').ljust(1000))
    f = open(filepath, 'rb')
    l = f.read(1000)
    while(l):
        s.send(l)
        l = f.read(1000)
    f.close()
    s.close()

def sendDelta(ip, port, username, filename, deltafile, targetService, cloudpath):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    s.send(bytes("{'op':3, 'user':'"+username+\
            "','filename':'"+filename+\
            "','deltaname':'"+deltafile.split('/')[-1]+"'}".ljust(1000), 'utf-8'))
    f = open(deltafile, 'rb')
    l = f.read(1000)
    while(l):
        #  print(l)
        s.send(l)
        l = f.read(1000)
    f.close()
    s.send("1".encode('utf-8'))
    t = s.recv(1)
    s.close()


if __name__ == "__main__":
    createUser(sys.argv[1], int(sys.argv[2]), 'test')
    while(True):
        registerFile(sys.argv[1], int(sys.argv[2]), 'test', '1.docx', './f100K.docx')
        #  shutil.copyfile('./1.docx', './old.docx')
        #  time.sleep(3)
        #  s = input()
        a = time.time()
        #  eng = diff.docdiff()
        #  eng.diff_zips('./f100K.docx', './f100K-a1b-1.docx')
        #  print("Diff: ",time.time() - a)
        sendDelta(sys.argv[1], int(sys.argv[2]), 'test', '1.docx', './f100K.patch', "dropbox", "/")
        print("Allt: ",time.time() - a)
