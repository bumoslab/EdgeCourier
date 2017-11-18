import os
import sys
import socket
import json
#  import dropbox.client
import dropbox
import urllib
import cmp as diff_patch
import time



#
#   Edge Part:
#
#   RegisterUser(self,[some information])
#
#   RegisterFile(self, file)
#   RecieveDelta(self, deltafile)
#   
#   ApplyDelta(self, oldfilen, deltafile)
#   Upload(self, file)
#


class dbUpload:
    app_key = 'ya5rgrxocoyrmx7'
    app_secret = 'ddy524aguk4j6lk'
    user_id = None
    access_token = 'WBjFx90NRQYAAAAAAAABcFeyhqwo32w3UtM-ELfVzZVIK3yg5N7jk1ibvJpWIixK'
    client = None

    def __init__(self):
        # flow = dropbox.client.DropboxOAuth2FlowNoRedirect(self.app_key, self.app_secret)
        # authorize_url = flow.start()
        # print('1. Go to: ' + authorize_url)
        # print('2. "Click "Allow" (you might have to log in first)')
        # print('3. Copy the authorization code.')
        # code = input("Enter the authorization code here: ").strip()

        # self.access_token, self.user_id = flow.finish(code)
        # print(self.user_id)

        self.client = dropbox.client.DropboxClient(self.access_token)
        #  print('linked account: ', self.client.account_info())

class docdiff:
    _queue = {}
    _tmproot = './diff' 

    def __init__(self):
        if not os.path.exists(os.path.abspath(self._tmproot)):
          os.makedirs(os.path.abspath(self._tmproot))

    def applyDelta(self, filename, deltaname):
        f = open(filename, 'rb')
        d = open(filename, 'rb')
        t = open(filename, 'wb')
        



class userspace:
    username = ''
    userinfo = {}

    userfolder = ''

    def __init__(self, username):
        self.username = username
        #  print(username)
        
    def recieveDelta(self, filename, deltafile, uploadPath):
        print("Need rewrite")

    def upload(self, filename):
        f = open(filename, 'rb')
        dbc = dbUpload()
        response = dbc.client.put_file(filename.split('/')[-1], f, overwrite=True)
        #  print("uploaded:", response)


def checkNet():
    print("==============[Network Connectable Checking ...]===================")
    try:
        sock = socket.create_connection(("216.58.217.100", 80), timeout=5)
        print(sock.getsockname())
        return sock.getsockname()[0]
    except Exception as e:
        print("Could not connect")
        sys.exit(0)
    print("==============[Network Connectable Finished    ]===================")


def main():
    userList = dict()
    print("Edge started")


    
    #  print(checkNet())
    ip = checkNet()
    
    # print(r)
    # hostname = socket.gethostname()
    # print(hostname)
    # IP = socket.gethostbyname(hostname)
    # print(IP)

    sock = socket.socket()
    ##########     Legacy    ################
    #  sock.bind(("192.168.122.68", 9999))  #
    #  sock.bind(("127.0.0.1", 9999))       #
    #  sock.bind(("10.32.135.251", 9999))   #
    ##########  Legacy End   ################



    sock.bind((sys.argv[1], int(sys.argv[2])))
    print("IP: ", ip, sys.argv[2])
    sock.listen(4)
    while True:
        sc, address = sock.accept()
        print(address)
        try:
            while True:
                data = sc.recv(1000).decode('utf-8')
                data = str(data)
                data = data.strip()
                #  print(data)
                data = data.replace("'", "\"")
                data = data.strip('\n')
                #  print(data)
                try:
                    dictt = json.loads(data) 
                except:
                    break

                # Register a User
                if dictt['op'] == 1:
                    u = userspace(dictt['user'])
                    userList[dictt['user']] = u 

                # Register a file
                elif dictt['op'] == 2:
                    print("Get File "+dictt['filename'])
                    if dictt['user'] in userList.keys():
                        f = open(dictt['filename'], 'wb')
                        f.seek(0)
                        data = sc.recv(1000)
                        while (data):
                            #  print(data)
                            #  print(len(data))
                            #data = data.decode('utf-8')
                            #data = str(data)
                            #data = data.strip()
                            if (data[len(data)-1] == 49 and len(data) < 1000):
                                f.write(data[:-1])
                                break
                            f.write(data)
                            data = sc.recv(1000)
                        f.truncate()
                        f.close()
                # Recieve a delta
                elif dictt['op'] == 3:
                    print("Get File "+dictt['filename'] + "'s delta")
                    diff = docdiff()
                    if dictt['user'] in userList.keys():
                        f = open(dictt['deltaname'], 'wb')
                        data = sc.recv(1000)
                        while (data):
                            #  print(data)
                            #data = data.decode('utf-8')
                            #data = str(data)
                            #data = data.strip()
                            if (data[len(data)-1] == 49 and len(data) < 1000):
                                f.write(data[:-1])
                                break
                            f.write(data)
                            data = sc.recv(1000)
                        f.close()
                        t1 = time.time()
                        engine = diff_patch.docdiff()
                        engine.patch_zips(dictt['filename'], dictt['deltaname'])
                        print("Patch! " ,time.time() - t1)
                    t1 = time.time()
                    u.upload(dictt['filename'])
                    print("Upload " ,time.time() - t1)
                    sc.send("1".encode('utf-8'))
        except Exception as e:
            print(e)
        sc.close()

    sock.close()




if __name__ == "__main__":
    main()
