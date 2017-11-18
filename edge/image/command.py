import subprocess
import sys
import os
import shutil
import threading
import time






def cleanup():
    for r, d, f in os.walk('.'):
        for i in f:
            if(i.startswith("python") and i.endswith(".bin") and ('-' in i)):
                os.remove(i)
                print(i)



def destroy():
    out = subprocess.check_output(["sudo", "xl", "list"])
    print out
    xlines = out.split('\n')
    for i in range(2,len(xlines)-1):
        xid = [ele for ele in xlines[i].split(" ") if ele][1]
        subprocess.Popen(["sudo", "xl", "destroy", xid])



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

def create(xid=0):
    pythonbin   = "python.bin"
    pythoniso   = "python.iso"
    #  mainprogram = "Edge_1.0-onedrive.iso"
    mainprogram = "Edge_1.0-dropbox.iso"
    ipaddr      = "0.0.0.0"
    port        = 10000 + xid
    mac         = "00:16:3e:00:0" 
    if (xid < 10):
        mac +="0:"
        mac += "0" + str(xid)
    elif(xid < 100):
        mac +="0:"
        mac += str(xid)
    else:
        mac += str(xid/100)
        mac += ":"
        xxid = xid % 100
        if (xxid < 10):
            mac += "0" + str(xxid)
        elif(xxid < 100):
            mac += str(xxid)


    # Create temp Binary:
    src = pythonbin
    dst = pythonbin.split('.')[0] + "-" + str(xid) + ".bin"
    shutil.copy(src, dst)
    
    command = [ "sudo",
                "../../../rumprun/rumprun/bin/rumprun",
                "xen",
                "-i",
                "-I",
                #  "newnet,xenif,bridge=xenbr0,mac=00:16:3e:00:00:04",
                "newnet,xenif,bridge=xenbr0,mac=" + mac,
                "-W",
                #  "newnet,inet,static,10.32.135.122/24",
                "newnet,inet,dhcp",
                "-M",
                "2048",
                "-b",
                pythoniso + ",/python/lib/python3.5",
                "-b",
                mainprogram + ",/python/lib/python3.5/site-packages",
                "-e",
                "PYTHONHOME=/python",
                "--",
                dst,
                "-m",
                "main",
                ipaddr,
                str(port)
            ]

    print(" ".join(command))
    #  p = subprocess.Popen(command, stdout=subprocess.PIPE)
    p = subprocess.Popen(command)
    p.wait()
    #  for i in p.stdout:
    #      if(i.startswith('IP')):
    #          print(i[i.find(' ')+2:])

def main(number):
    testnumber  = number 
    threads = []
    for i in range(0, testnumber):
        threads.append(crThread(i))

    for i in threads:
        i.start()
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
