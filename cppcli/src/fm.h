#include <iostream>
#include <fstream>
#include <string>
#include <map>


#define MAXSZ 9999


class filemanager{

private:
	std::map<std::string, std::string> fileList;
	
public:
	int length;
	const char* root = "./backup";

	filemanager();

	std::string addFile(std::string filename, std::string path);

	int removeFile(std::string filename);

	std::string updateFile(std::string filename, std::string path);

	int exists(std::string filename);

	std::string getValue(std::string filename);

	std::string getBackupPath(std::string filename);
};
