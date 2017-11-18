import os
import shutil
import zipfile
import inotify.adapters
from cmp import docdiff 


def isDocument(name):
    name = name.split('.')[-1]
    if name in ['txt','docx','pptx','xlsx']:
        return True
    return False

class trigger:
    _handlers = {}


class doclist:
    _doclist = {}
    tmproot = './tmp'

    def __init__(self):
        if not os.path.exists(os.path.abspath(self.tmproot)):
            os.makedirs(os.path.abspath(self.tmproot))


    def consume(self, types, path, filename):
        print types,filename
        absfilename = path + '/' + filename
        if 'IN_ISDIR' in types or not isDocument(filename):
            return
        if 'IN_OPEN' in types:
            self._fopen(absfilename)
        if 'IN_CLOSE_WRITE' in types:
            self._fclose(absfilename)
            cmpengine = docdiff()

            dstroot = os.path.abspath(self.tmproot)
            dst = os.path.join(dstroot, filename.split('/')[-1])
            old_doc_path = dst 
            cmpengine.consume(old_doc_path, absfilename)
            

            self._tmp_remove_backup(absfilename)
        if 'IN_CLOSE_NOWRITE' in types:
            self._fclose(absfilename)


    def _fopen(self, filename):
        if filename in self._doclist.keys():
            self._doclist[filename][0] += 1
        else:
            self._doclist[filename] = [1,0]
            self._tmp_backup(filename)

    def _tmp_backup(self, filename):
        assert not os.path.isabs(filename)
        dstroot = os.path.abspath(self.tmproot)
        dst = os.path.join(dstroot, filename.split('/')[-1])
        shutil.copy(filename, dst)
        

    def _fclose(self, filename):
        self._doclist[filename][1] += 1
        if self._doclist[filename][1] == 0:
            del self._doclist[filename]

    def _tmp_remove_backup(self, filename):
        assert not os.path.isabs(filename)
        dstroot = os.path.abspath(self.tmproot)
        dst = os.path.join(dstroot, filename.split('/')[-1])
        #os.remove(dst)
        


    def __str__(self):
        return str(self._doclist)


def _main():
    iHandler = inotify.adapters.Inotify()
    flist = doclist()

    iHandler.add_watch(b'../res')
    try:
        for event in iHandler.event_gen():
            if event is not None:
                (header, types, path, filename) = event
                flist.consume(types, path, filename)
                
                #print types,filename
                print flist
    finally:
        iHandler.remove_watch(b'../res')


_main()
myzip = zipfile.ZipFile('../res/1.docx', 'r')

print myzip.namelist()
