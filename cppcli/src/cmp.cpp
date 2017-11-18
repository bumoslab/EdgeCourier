#include "cmp.h"

std::string getFiletype_FromPath(std::string path){
	if(path.rfind('.') == std::string::npos){
		return path;
	}
	return std::string(path.substr(path.rfind('.') + 1));
}

std::string getFilename_FromPath(std::string path){
	if(path.rfind('/') == std::string::npos){
		return path;
	}
	return std::string(path.substr(path.rfind('/') + 1));
}

std::string getFoldername_FromPath(std::string path){
	if(path.rfind('/') == std::string::npos){
		return std::string("");
	}
	return std::string(path.substr(0, path.rfind('/')));	
}

std::string getRelativePath(std::string path, std::string basePath){
#ifdef DEBUG
	// std::cout << "[Get Relative Path]" << path << " - " << basePath << std::endl;
#endif
	std::string pathWithoutFile = getFoldername_FromPath(path);
	if(basePath.length() >= pathWithoutFile.length()){
		return std::string("");
	}
	return std::string(pathWithoutFile.substr(basePath.length() + 1));
}

std::list<std::string> walkDirectory(std::string targetName){
	const char* target = targetName.c_str();
	DIR* targetDir = opendir(target);
	struct dirent *entry;

	std::list<std::string> ret;

	if(target == NULL){
		// std::cout << "[" << __func__ << "]" << std::endl;
	}
	while((entry = readdir(targetDir))){
		if(entry->d_type == 4){
			if(entry->d_name[0] == '.'){
				// This doesn't think about in linux fs,
				// hide files's name also start with '.', TODO
				continue;
			}else{
				std::list<std::string> sublist = walkDirectory(targetName + \
						"/" + entry->d_name);
				ret.merge(sublist);
			}

		}else if (entry->d_type == 8){
			ret.push_back(targetName + "/" + entry->d_name);
		}
	}
	closedir(targetDir);
	ret.sort();
	return ret;
}


int uncompressFile(std::string filename, std::string targetDirectory){
	int err;
	zip *z = zip_open(filename.c_str(), 0, &err);	// zipfile pointer
	struct zip_stat st;						// zipfile stat structure
	struct zip_file *zf;					// file pointer in zip archive

	mkdir_r(std::string(targetDirectory), 0700);
	zip_stat_init(&st);						
	for (int i = 0; i < zip_get_num_entries(z, 0); i++) {
		if (zip_stat_index(z, i, 0, &st) == 0) {
			// printf("==================\n");
			int len = strlen(st.name);
			// printf("Name: [%s], ", st.name);
			// printf("Size: [%llu], ", (unsigned long long)st.size);
			// printf("mtime: [%u]\n", (unsigned int)st.mtime);
			if(st.name[len - 1] == '/'){
				std::cout<< st.name << " creating" <<std::endl;
			}else{
				zf = zip_fopen_index(z, i, 0);

				// Get Necessary Names 
				std::string filename = std::string(st.name);
				std::string pathname = getFoldername_FromPath(filename);
				filename = getFilename_FromPath(filename);

				// Create Necessary Dirs
				mkdir_r(std::string(targetDirectory) + "/" + pathname,\
						0707);

				std::string tmpfile = std::string(targetDirectory) + "/" + \
									  pathname + "/" +\
									  filename;
				std::ofstream tmpOut(&tmpfile[0u],std::ofstream::out);	   
				long long sum = 0, rsz = 0;
				while(sum < (long long)st.size){
					char buf[101] = {0};
					rsz = zip_fread(zf, buf, 100);
					tmpOut << buf;
					sum += rsz;
				}
				tmpOut.close();
				zip_fclose(zf);
			}
		}
	}
	return 1;
}


int compressDir(std::string dirName, std::string targetZipName){
	int err;
	zip *z = zip_open(targetZipName.c_str(), ZIP_CREATE|ZIP_TRUNCATE, &err);
	// std::cout<<(z==NULL)<<std::endl;
	zip_source_t *src;

	std::list<std::string> files = walkDirectory(dirName);	

	// if(files.begin() == files.end()){
	//     std::cout << "No File" << std::endl;
	//     zip_close(z);
	//     return 1;
	// }

	for(std::list<std::string>::iterator i = files.begin();\
			i != files.end(); ++i){
		// std::cout<< *i <<std::endl;

		char qfile[150] = {0};
		strcpy(qfile, i->c_str());

		src = zip_source_file(z, qfile, 0, -1);

		std::string ti = std::string(*i);
		std::string tii = getRelativePath(ti, dirName) + '/' + getFilename_FromPath(*i);
		// std::cout << tii << std::endl;
		zip_file_add(z, tii.c_str(), src, ZIP_FL_ENC_UTF_8);
		// std::cout << "=============[EOA]=============" <<std::endl;
	}
	zip_close(z);
	return 1;
}


QString makePatch_Files(char* filename1, char* filename2){
	FILE* file1 = fopen(filename1, "r");
	FILE* file2 = fopen(filename2, "r");

	if(file1 == NULL || file2 == NULL){
		printf("[makePatch_Files] File Can't be opened.\n");
		std::cout << "Filename is " << filename1 << " | " << filename2 << std::endl;
	}


	// std::cout << "Before read" << std::endl;
	std::ifstream inFile;
	inFile.open(filename1, std::ifstream::in);
	std::stringstream strStream1;
	strStream1 << inFile.rdbuf();
	std::string content1 = strStream1.str();
	inFile.close();

	inFile.open(filename2, std::ifstream::in);
	std::stringstream strStream2;
	strStream2 << inFile.rdbuf();
	std::string content2 = strStream2.str();
	inFile.close();
	// std::cout << "After read" << std::endl;
	// std::cout << "Before deal" << std::endl;
	// long long len = content1.length();
	// for(long long i=len-1; i>=0 ; i++){
	//     if(content1[i] == '>'){
	//         content1.insert(i, "\n");
	//     }
	// }
	// len = content2.length();
	// for(long long i=len-1; i>=0 ; i++){
	//     if(content2[i] == '>'){
	//         content2.insert(i, "\n");
	//     }
	// }
	// std::cout << "After deal" << std::endl;
	// Get file size (bytes)
	// fseek(file1, 0, SEEK_END);
	// length = ftell(file1);
	// fseek(file1, 0, SEEK_SET);
	//
	// char* content1 = (char*)malloc(length-1);
	// fread(content1, 1, length, file1);

	// fseek(file2, 0, SEEK_END);
	// length = ftell(file1);
	// fseek(file2, 0, SEEK_SET);
	//
	// char* content2 = (char*)malloc(length);
	// fread(content2, 1, length, file2);

	// std::cout << "========================" << std::endl;
	// std::cout << content1 << std::endl;
	// std::cout << "========================" << std::endl;
	// std::cout << content2 << std::endl;

	// printf("%s \n\n\n\n %s", content1, content2);
	QString con1 = QString::fromStdString(content1);
	QString con2 = QString::fromStdString(content2);

	diff_match_patch eng = diff_match_patch();
	QList<Patch> res = eng.patch_make(con1, con2);

	QString resStr = eng.patch_toText(res);

	// qDebug() << resStr;
	// qDebug() << resStr.length();

	// strcpy(resStr.toLatin1().data(), retStr);
	// std::cout << retStr << std::endl;

	return resStr;
}


QString makePatch_Files_2(char* filename1, char* filename2){
	std::string f1 = std::string(filename1);
	std::string f2 = std::string(filename2);
	char buffer[128];
	std::string result = "";

	std::string cmd = std::string("sed 's/\\(.\\)/\\1\\n/g' -i ") + f1; 
	FILE* pipe = popen(cmd.c_str(), "r");
	if (!pipe) throw std::runtime_error("popen() failed!");
	cmd = std::string("sed 's/\\(.\\)/\\1\\n/g' -i ") + f2; 
	pipe = popen(cmd.c_str(), "r");
	if (!pipe) throw std::runtime_error("popen() failed!");
	cmd = std::string("diff -uNr ") + f1 + std::string(" ") + f2; 
	std::cout << cmd << std::endl;
	pipe = popen(cmd.c_str(), "r");
	if (!pipe) throw std::runtime_error("popen() failed!");
	try {
		while (!feof(pipe)) {
			if (fgets(buffer, 128, pipe) != NULL)
				result += buffer;
		}
	} catch (...) {
		pclose(pipe);
		throw;
	}
	pclose(pipe);

	QString resStr = QString::fromStdString(result);

	return resStr;
}

int storePatch(QString patch, char* filename){
	FILE* file = fopen(filename, "w");
	fwrite(patch.toLatin1().data(), sizeof(char), patch.length(), file);
	fclose(file);
	return 1;
}


int mkdir_r(std::string dirname, const mode_t mode){
#ifdef DEBUG
	std::cout<<"Creating Folder " << dirname << std::endl;
#endif
	struct stat st;
	int flag = 1;
	int size = dirname.length();
	if(size <= 2 )
		return -1;

	for(int i = 0; i < size; i++){
		if(dirname[i] == '/'){
			char tmpstr[120] = {0};
			strcpy(tmpstr, std::string(dirname.substr(0, i)).c_str());
			// std::cout << dirname.substr(0, i).size() << " " << strlen(tmpstr) << " " ; 
			// std::cout<< stat(tmpstr, &st) << std::endl;
			if(stat(tmpstr, &st) == -1){
				// std::cout <<"[Inner] " << tmpstr << std::endl;
				flag += mkdir(tmpstr, mode);
			}
		}
	}
	char tmpstr[120] = {0};
	strcpy(tmpstr, dirname.c_str());
	// std::cout<< strlen(tmpstr) << std::endl;
	if(stat(tmpstr, &st) == -1){
		// std::cout <<"[Last] " << tmpstr << std::endl;
		flag += mkdir(tmpstr, mode);
	}
	return flag;
}



std::string makePatch_Dirs(std::string directory1, std::string directory2){
#ifdef DEBUG
	std::cout<< "[makePatch_Dirs] " << directory1 << " " \
		<<directory2 << std::endl;
#endif	
	std::list<std::string> newFiles = walkDirectory(std::string(directory2));
	int length = newFiles.size();
	int dlen = directory2.length();
	for(int i=0; i<length; i++){
		const char* tmpStr = newFiles.front().c_str() + dlen;
		newFiles.push_back(std::string(tmpStr));
		newFiles.pop_front();
	}

	// Create a tmp folder
	std::string tmpDirName = std::string(DIFF_TMP_DIR) + "/" +\
							 std::string(getFilename_FromPath(directory2));	  
	struct stat st;
	std::cout << tmpDirName << std::endl;
	if(stat(tmpDirName.c_str(), &st) == -1){
		std::cout<<mkdir_r(&tmpDirName[0u], 0700)<<std::endl;
	}


	// Iterator files in new version directory
	for(std::list<std::string>::iterator i = newFiles.begin();\
			i != newFiles.end(); ++i){
		std::string oldfilename = std::string(directory1) + *i;
		std::string newfilename = std::string(directory2) + *i;
		std::cout << getFiletype_FromPath(oldfilename) << std::endl;
		if(getFiletype_FromPath(oldfilename).compare(std::string("rels")) != 0 &&
				getFiletype_FromPath(oldfilename).compare(std::string("xml")) != 0){
			continue;		
		}
#ifdef DEBUG
		std::cout<< oldfilename << " " << newfilename << std::endl;
#endif
		QString patch = makePatch_Files(&oldfilename[0u],\
				&newfilename[0u]);
		if(patch==""){
			// std::cout<<oldfilename<<std::endl;
		}else{
			// std::cout<<"[Changed] " << oldfilename<<std::endl;
			std::string baseFolder = tmpDirName + "/" +\
									 getRelativePath(newfilename, std::string(directory2));

			if(stat(baseFolder.c_str(), &st) == -1){
				mkdir_r(&baseFolder[0u], 0700);
			}
			std::string tmpPatchFileName = tmpDirName + "/" \
										   + getRelativePath(newfilename, std::string(directory2)) + "/" \
										   + getFilename_FromPath(newfilename);
#ifdef DEBUG
			std::cout << tmpPatchFileName << std::endl;
#endif
			std::ofstream patchfile(tmpPatchFileName.c_str(), std::ofstream::out);
			if(!patchfile){
				std::cout<< "Wrong with " << oldfilename << std::endl;
				continue;
			}
			patchfile << patch.toLatin1().data(); 
			patchfile.close();
		}
	}	
	return tmpDirName;
}

std::string makePatch_Zips(std::string zipfile1, std::string zipfile2){
	std::string zipname = getFilename_FromPath(zipfile2);
	std::string tmpZipName = std::string(DIFF_TMP_DIR) + std::string("/") +\
							 zipname + ".zip"; 
	time_t t =time(0);
	zipname += std::string("_") + SSTR(t);

	std::string oldDirName = std::string(DIFF_DIR) + std::string("/") + zipname + std::string("/old");
	std::string newDirName = std::string(DIFF_DIR) + std::string("/") + zipname + std::string("/new");

	uncompressFile(zipfile1, oldDirName); 
	uncompressFile(zipfile2, newDirName); 

	std::string targetDir = makePatch_Dirs(oldDirName, newDirName);

	compressDir(targetDir, tmpZipName); 

	return tmpZipName;
}

// int main(int argc, char*argv[]){
//     if(argc <= 1){
//         printf("[Main] Error with argc\n");
//         exit(0);
//     }
//     // This is test code for make patch of files
//     //
//     // QString patch = makePatch_Files(argv[1], argv[2]);
//     // std::cout << patch.toLatin1().data() << std::endl;
//     //
//
//     // This is test code for make patch of two dirs
//
//     //     if(!makePatch_Dirs(argv[1], argv[2]))
//     //         std::cout<< "fuck" <<std::endl; */
//     //
//     //             std::string oldfile = std::string(argv[1]);
//     // std::string newfile = std::string(argv[2]);
//     // uncompressFile(oldfile, std::string(DIFF_DIR) + std::string("/old"));
//     // uncompressFile(newfile, std::string(DIFF_DIR) + std::string("/new"));
//     //
//     // makePatch_Dirs(std::string(DIFF_DIR) + std::string("/old"), \
//     //         std::string(DIFF_DIR) + std::string("/new"));
//     //
//     //     // makePatch_Zips(std::string(argv[1]), std::string(argv[2]));
//     //     // compressDir(std::string("./diff_tmp/new"), std::string("test.zip"));
//     //
//     struct timeval t1, t2;
//     gettimeofday(&t1, NULL);
//     std::cout << makePatch_Zips(std::string(argv[1]), std::string(argv[2])) << std::endl;
//
//     gettimeofday(&t2, NULL);
//     int milliSeconds = (t2.tv_sec - t1.tv_sec) * 1000 + (t2.tv_usec - t1.tv_usec)/1000;
//     printf ("Diffs %d\n", milliSeconds);
// }
