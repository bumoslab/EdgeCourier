import subprocess
import sys
import os
import shutil
import threading
import time


def help():
    print("Usage:\n \
            python command.py testnumber \n \
            \n")

#  print_lock = threading.Lock()
class crThread(threading.Thread):
    def __init__(self, xid):
        threading.Thread.__init__(self)
        self.xid = xid

    def run(self):
        print("start" + str(self.xid))
        create(self.xid)
        run(self.xid)
        
def create(did):
    #  sudo docker build -t dropbox/fc001 .
    f = open("Dockerfile", "w")
    lines = ["FROM python:3.5",
            "MAINTAINER Pengzhan Hao <haopengzhan@gmail.com>",
            "",
            "",
            "RUN mkdir -p /app",
            "WORKDIR /app",
            "",
            "ADD requirements.txt requirements.txt",
            "RUN pip3 install -r requirements.txt",
            "ADD cmp.py cmp.py",
            "ADD main.py main.py",
            "",
            "EXPOSE " + str(10000+did),
            "ENTRYPOINT [\"python3\"]",
            "CMD [\"main.py\", \"0\", \"" + str(10000+did) +"\"]"
            ]

    print("\n".join(lines))
    for i in lines:
        f.write(i + "\n")

    f.flush()
    f.close()

    name = "dropbox/fc" + "{0:03}".format(did)

    command = ["sudo",
                "docker",
                "build",
                "-t",
                name,
                "."
                ]
    print(" ".join(command))
    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    p.wait()


def run(did):
    # sudo docker run -p 9999:9999 dropbox/fc001

    port = str(10000+did)
    name = "dropbox/fc" + "{0:03}".format(did)
    command = [ "sudo",
                "docker",
                "run",
                "-p",
                port + ":" + port ,
                name
            ]

    print(" ".join(command))
    p = subprocess.Popen(command) 

def main(number):
    testnumber  = number 
    threads = []
    for i in range(1, testnumber+1):
        #  create(i)
        threads.append(crThread(i))

    for i in threads:
        i.run()
        time.sleep(1)



if __name__ == "__main__":
    if(len(sys.argv) < 2):
        help()
        sys.exit(0)

    if(sys.argv[1] == "create"):
        main(int(sys.argv[2]))
    if(sys.argv[1] == "clean"):
        destroy()
        cleanup()
