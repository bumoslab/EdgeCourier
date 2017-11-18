import os
import sys
import socket
import json
import time
import requests
# import dropbox
import onedrivesdk
from onedrivesdk.helpers import GetAuthCodeServer
import cmp as diff_patch



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
    #  app_key = 'ya5rgrxocoyrmx7'
    #  app_secret = 'ddy524aguk4j6lk'
    #  user_id = None

    # dropbox auth
    #  access_token = 'WBjFx90NRQYAAAAAAAABBCZ-PJqKLZNIe1sO1Z0msDeORdA-K4Dba95MgmmfPIfp'
    client = None

    def __init__(self):
        print("==========  Creating Service  ==========")
        # flow = dropbox.client.DropboxOAuth2FlowNoRedirect(self.app_key, self.app_secret)
        # authorize_url = flow.start()
        # print '1. Go to: ' + authorize_url
        # print '2. "Click "Allow" (you might have to log in first)'
        # print '3. Copy the authorization code.'
        # code = raw_input("Enter the authorization code here: ").strip()

        # self.access_token, self.user_id = flow.finish(code)
        # print self.user_id


        #  self.client = dropbox.client.DropboxClient(self.access_token)
        #  print('linked account: ', self.client.account_info())

    def printAuth(self):
        self.redirect_uri = 'http://localhost/'
        self.client_id='41ec11be-5b42-466e-94b4-4f31b9cd7b4c'
        self.client_secret = 'O7Bwmr7HTNos34PniF69HVO'
        self.scopes=['wl.signin', 'wl.offline_access', 'onedrive.readwrite']
        self.api_base_url='https://api.onedrive.com/v1.0/'

        http_provider = onedrivesdk.HttpProvider()
        auth_provider = onedrivesdk.AuthProvider(
                http_provider=http_provider,
                client_id=self.client_id,
                scopes=self.scopes)

        self.client = onedrivesdk.OneDriveClient(self.api_base_url, auth_provider, http_provider)
        auth_url = self.client.auth_provider.get_auth_url(self.redirect_uri)

        print('Paste this URL into your browser, approve the app\'s access.')
        print('Copy everything in the address bar after "code=", and paste it below.')
        print(auth_url)
        return auth_url
    def getAuth(self, code):
        if code == None:
            code = input('Paste code here: ')
        try:
            self.client.auth_provider.authenticate(code, self.redirect_uri, self.client_secret)
        except Exception as e:
            print("")
            print("[Get Auth Error]: " + str(e))
            print("")


def filetype(name):
    filetype = name.split('.')[-1]
    if filetype in ['docx','doc','pptx','ppt','xls','xlsx','odt','ods']:
        return 2
    if filetype in ['txt','dat','md']:
        return 1
    return 0



class userspace:
    username = ''
    userinfo = {}

    userfolder = ''

    def __init__(self, username):
        print(username)
        self.dbc = dbUpload()

    def recieveDelta(self, filename, deltafile, uploadPath):
        print("Need rewrite")

    def upload(self, filename):
        a = time.time()
        response= self.dbc.client.item(drive='me', id='root').children[filename.split('/')[-1]].upload(filename)
        print("==============[     Upload Time     ]===================")
        print("uploaded:", response, str(time.time()-a))

def checkNet():
    print("==============[Network Connectable Checking ...]===================")
    try:
        sock = socket.create_connection(("216.58.217.100", 80), timeout=5)
        print(sock)
    except Exception as e:
        print("Could not connect")
        sys.exit(0)
    print("==============[Network Connectable Finished    ]===================")
    


def main():
    userList = dict()
    checkNet()

    print("Edge started")
    
    #  hostname = socket.gethostname()
    #  print(hostname)
    #  IP = socket.gethostbyname(hostname)
    #  print(IP)

    sock = socket.socket()
    ##########     Legacy    ################
    #  sock.bind(("192.168.122.68", 9999))  #
    #  sock.bind(("127.0.0.1", 9999))       #
    #  sock.bind(("10.32.135.251", 9999))   #
    ##########  Legacy End   ################



    sock.bind((sys.argv[1], int(sys.argv[2])))
    sock.listen(4)
    while True:
        sc, address = sock.accept()
        print(address)

        # Start 
        data = sc.recv(128).decode('utf-8')
        data = str(data)
        data = data.strip()
        data = data.replace("'", "\"")
        data = data.strip('\n')
        data = data.strip('\0')


        #  try:
        dictt = json.loads(data) 

        # Register a User
        if dictt['op'] == 1:

            # Get Initial Code
            code = sc.recv(128).decode('utf-8')
            code = str(code)
            code = code.strip()
            code = code.strip('\n')
            code = code.strip('\0')

            print('register: ' + dictt['user'])
            print('Init Code: ' + code)
            if dictt['user'] not in userList.keys():
                u = userspace(dictt['user'])
                userList[dictt['user']] = u 
            if(code != ""):
                u.dbc.printAuth()
                u.dbc.getAuth(code)

        # Register a file
        elif dictt['op'] == 2:
            print("Get File "+dictt['filename'])
            if dictt['user'] in userList.keys():
                f = open(dictt['filename'], 'wb')
                f.seek(0)
                data = sc.recv(128)
                while (data):
                    f.write(data)
                    data = sc.recv(128)
                f.truncate()
                f.close()
            sc.send("1".encode('utf-8'))

        # Recieve a delta
        elif dictt['op'] == 3:
            print("Get File "+dictt['filename'] + "'s delta")
            if dictt['user'] in userList.keys():
                u = userList[dictt['user']]
                f = open(dictt['deltaname'], 'wb')
                data = sc.recv(128)
                while (data):
                    if (data[len(data)-1] == 49 and len(data) < 128):
                        f.write(data[:-1])
                        break
                    f.write(data)
                    data = sc.recv(128)
                f.close()
                engine = diff_patch.docdiff()
                try:
                    a = time.time()
                    t = filetype(dictt['filename'])
                    if(t==2):
                        engine.patch_zips(dictt['filename'], dictt['deltaname'])
                    elif(t==1):
                        enging.patch_files(dictt['filename'], dictt['deltaname'])
                    else:
                        print("No valid file type")
                    print("patch ", time.time()-a)
                except Exception as e:
                    print(e)
            lastname = dictt['filename']

            try:
                u.upload(dictt['filename'])
            except Exception as e:
                print("Error with upload")
                u.dbc.printAuth()
                sc.send("2".encode('utf-8'))
                while True:
                    data = ""
                    data = sc.recv(128).decode('utf-8')
                    if str(data) != "":
                        print("Get Code" + str(data))
                        break

                u.dbc.getAuth(data)
                u.upload(dictt['filename'])
            finally:
                sc.send("1".encode('utf-8'))


            # Close
        #  elif dictt['op'] == 4:
        #      print("Get Auth "+dictt['code'])

        #  except Exception as e:
        #      print(e)

        sc.close()

    sock.close()




if __name__ == "__main__":
    main()
