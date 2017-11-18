#include "fm.h"
#include "cmp.h"



filemanager::filemanager(){
	this->fileList = std::map<std::string, std::string>();
	this->length = 0;
	mkdir_r(std::string(this->root), 0777);

}

std::string filemanager::addFile(std::string filename, std::string path){
	if(path.compare(std::string("")) == 0){
		path = std::string("./") + filename;
	}
	std::string dstpath = std::string(this->root) + std::string("/") + getFilename_FromPath(filename);
	// std::cout << path << " | " << dstpath <<std::endl;
	// char tmpRoute[100] = {0};
	// strcpy(tmpRoute, path.c_str());
	std::ifstream src(path.c_str(), std::ios::binary);
	// char tmpRoute1[100] = {0};
	// strcpy(tmpRoute1, dstpath.c_str());
	// std::cout << tmpRoute1 << std::endl;
	std::ofstream dst(dstpath, std::ios::binary);

	// std::cout << src.rdbuf();
	dst << src.rdbuf();
	src.close();
	dst.close();

	this->fileList.insert(std::pair<std::string, std::string>(filename, path));
	this->length += 1;
	return dstpath;
}

int filemanager::removeFile(std::string filename){
	this->fileList.erase( \
			this->fileList.find(filename));
	this->length-= 1;
	return this->length;
}

std::string filemanager::updateFile(std::string filename, std::string path){
	if(path.compare(std::string("")) == 0){
		path = std::string("./") + filename;
	}
	std::string dstpath = std::string(this->root) + std::string("/") + getFilename_FromPath(filename);
	// std::cout << path << " | " << dstpath <<std::endl;
	// char tmpRoute[100] = {0};
	// strcpy(tmpRoute, path.c_str());
	std::ifstream src(path.c_str(), std::ios::binary);
	// char tmpRoute1[100] = {0};
	// strcpy(tmpRoute1, dstpath.c_str());
	// std::cout << tmpRoute1 << std::endl;
	std::ofstream dst(dstpath, std::ios::binary);

	// std::cout << src.rdbuf();
	dst << src.rdbuf();
	src.close();
	dst.close();

	return dstpath;
}

bool equalFiles(std::ifstream& in1, std::ifstream& in2)
{
	std::ifstream::pos_type size1, size2;

	size1 = in1.seekg(0, std::ifstream::end).tellg();
	in1.seekg(0, std::ifstream::beg);

	size2 = in2.seekg(0, std::ifstream::end).tellg();
	in2.seekg(0, std::ifstream::beg);

	if(size1 != size2)
		return false;

	static const size_t BLOCKSIZE = 4096;
	size_t remaining = size1;

	while(remaining)
	{
		char buffer1[BLOCKSIZE], buffer2[BLOCKSIZE];
		size_t size = std::min(BLOCKSIZE, remaining);

		in1.read(buffer1, size);
		in2.read(buffer2, size);

		if(0 != memcmp(buffer1, buffer2, size))
			return false;

		remaining -= size;
	}

	return true;
}

int filemanager::exists(std::string filename){
	if(this->fileList.find(filename) != this->fileList.end()){
		goto check;
	}
	return 0;

check:
	std::ifstream in1(filename.c_str(), std::ios::binary);
	std::ifstream in2(this->getBackupPath(filename).c_str(), std::ios::binary);
	if(equalFiles(in1, in2)){
		std::cout<< "eqaul" <<std::endl;
		return 2;
	}else{
		return 1;
	}
}

std::string filemanager::getValue(std::string filename){
	return this->fileList[filename];
}

std::string filemanager::getBackupPath(std::string filename){
	return std::string(this->root) + std::string("/") + filename;
}

