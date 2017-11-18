import os
import time
import zipfile
import difflib
import shutil
import sys
from diff_match_patch.diff_match_patch import diff_match_patch as dmp
# import diff_match_patch as dmp
# from diff_mat import diff_match_patch as dmp

class docdiff:
    _queue = {}
    _tmproot = './diff' 

    def __init__(self):
        self.google_engine = dmp()
        if not os.path.exists(os.path.abspath(self._tmproot)):
            os.makedirs(os.path.abspath(self._tmproot))


    def uncompress(self, targetfile, targetpath):
        myzip = zipfile.ZipFile(targetfile, 'r')
        myzip.extractall(self._tmproot+'/'+targetpath+'/'+targetfile.split('/')[-1])
        myzip.close()
        # print myzip.namelist()
        
    def diff_zips(self, doc1, doc2):
        self.uncompress(doc1, 'old')
        self.uncompress(doc2, 'new')

        docname = doc1.split('/')[-1]
        if docname != doc2.split('/')[-1]:
            print("Error with name of two version documents")
        old_file_dir = self._tmproot + '/old/' + doc1.split('/')[-1]
        new_file_dir = self._tmproot + '/new/' + doc2.split('/')[-1]
        self.diff_dirs(old_file_dir, new_file_dir)
        patch_root = './patch_dir/' + doc2.split('/')[-1]
        ziph = zipfile.ZipFile(docname.split('.')[0]+".patch", 'w', zipfile.ZIP_DEFLATED)   #TODO Correct Filename
        for root, dirs, files in os.walk(patch_root):
            # print root
            for f in files:
                fname = root + '/' + f
                ziph.write(fname, fname[len(patch_root):])
        ziph.close()
        shutil.rmtree(patch_root)

    def patch_zips(self, old_doc, patch_doc):
        self.uncompress(old_doc, 'target')
        self.uncompress(patch_doc, 'patch')

        patchname = patch_doc.split('/')[-1]
        docname = old_doc.split('/')[-1]

        patch_dir = self._tmproot + '/patch/'+ patchname 
        old_file_dir = self._tmproot + '/target/' + docname
        self.patch_dirs(patch_dir, old_file_dir)
        ziph = zipfile.ZipFile(docname, 'w', zipfile.ZIP_DEFLATED)   #TODO Correct Filename
        for root, dirs, files in os.walk(old_file_dir):
            #  print(root)
            for f in files:
                fname = root + '/' + f
                ziph.write(fname, fname[len(old_file_dir):])
        ziph.close()
        shutil.rmtree(patch_dir)
        shutil.rmtree(old_file_dir)



    def diff_dirs(self, odname, ndname):
        patch_root = './patch_dir/' + ndname.split('/')[-1]
        for root, dirs, files in os.walk(ndname):
            # print root, dirs, files
            for ifile in files:
                tmproot = root[len(ndname):]

                proot = patch_root + tmproot

                tmproot = odname + tmproot
                if os.path.exists(tmproot+"/"+ifile):
                    diff = self.diff_files(tmproot+"/"+ifile, root+"/"+ifile)
                    # print diff
                    if not diff:
                        # print ifile + " same"
                        continue
                    else:
                        # print ifile + " not same"
                        if not os.path.exists(os.path.abspath(proot)):
                            os.makedirs(os.path.abspath(proot))
                        pfile = open(proot+"/"+ifile, 'wb')
                        flush_content = self.diff_files(tmproot+"/"+ifile, root+"/"+ifile)
                        # print flush_content
                        flush_content = bytes(self.PatchtoText(flush_content), 'utf-8')
                        # print flush_content
                        # flush_content.encode('utf-8')
                        pfile.write(flush_content)
                        pfile.close()
                else:
                    if not os.path.exists(os.path.abspath(proot)):
                        os.makedirs(os.path.abspath(proot))
                    pfile = open(proot+"/"+ifile, 'wb')
                    print("No such a file in old version")
                    pfile.write(open(root+"/"+ifile, 'rb').read())
                    pfile.close()

    def patch_dirs(self, patch_dir, odname):
        #  print("Patch Dirs Start")
        patch_root = patch_dir
        #  print(patch_root)
        for root, dirs, files in os.walk(patch_root):
            for ifile in files:
                #  print(ifile)
                old_tmp_root = root[len(patch_root):]
                old_tmp_root = odname + old_tmp_root
                # print old_tmp_root
                #  print("updating file" + old_tmp_root+"/"+ifile)
                if os.path.exists(old_tmp_root+"/"+ifile):
                    p = open(root+"/"+ifile, 'rb')                    
                    d = p.read().decode('utf-8')
                    # print d
                    d = self.PatchFromText(d)
                    # print d
                    self.patch_files(old_tmp_root+"/"+ifile, d) 
                else:
                    shutil.copyfile(old_tmp_root+"/"+ifile, root+"/"+ifile)


    def diff_files(self, ofname, nfname):
        # diff = difflib.Differ().compare(open(ofname, 'r').readlines(), open(nfname, 'r').readlines())
        #  print(ofname, nfname)
        f1 = open(ofname, 'rb').read()
        f2 = open(nfname, 'rb').read()
        f1 = f1.decode('utf-8')
        f2 = f2.decode('utf-8')
        # print(f1, f2)
        diff = self.google_engine.patch_make(f1, f2)
        #  print(diff)
        return diff

    def patch_files(self, ofname, patch):
        f = open(ofname, 'rb+')
        c = f.read()
        c = c.decode('utf-8')
        recover = self.google_engine.patch_apply(patch, c)
        content = recover[0].encode('utf-8')
        f.seek(0)
        f.write(content)
        f.truncate()
        f.close()
        
    def PatchtoText(self, patch):
        return self.google_engine.patch_toText(patch) 
    def PatchFromText(self, patch):
        return self.google_engine.patch_fromText(patch)


if __name__ == "__main__":
    d =docdiff()
    d.diff_zips(sys.argv[1], sys.argv[2])
    # d.patch_zips("../res/old/1.docx", "./1.patch")
    # d.diffzips("1.docx")
    # d.diff_dirs("./diff/old/1.docx", "./diff/new/1.docx")
    # p = d.diff_files("./diff/old/1.docx/word/document.xml", "./diff/new/1.docx/word/document.xml")
    # print p
    # p = d.patch_files("./diff/old/1.docx/word/document.xml", p)
    # print p
    # time.sleep(10)
    # d.patch_dirs('./patch_dir/1.docx', './diff/old/1.docx')
