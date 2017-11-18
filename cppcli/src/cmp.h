#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <stdlib.h>
#include <stdio.h>
#include <stdexcept>
#include <sys/time.h>

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>


#include <zip.h>

#include <QtCore/qstring.h>
#include "diff_match_patch.h"

// #define DEBUG



// Metadata

#define DIFF_DIR "./diff_gen"
#define DIFF_TMP_DIR "./diff_tmp"


// Marco

#define SSTR( x ) static_cast< std::ostringstream & >( \
		( std::ostringstream() << std::dec << x ) ).str()

/***************************************
 *  Utils
 ***************************************/

/**
 * Sequentially create a nested folder
 * @param dirname Final dir name
 * @param mode the mode of each level dirs
 * @return status 0 or 1
 */
int mkdir_r(std::string dirname, const mode_t mode);

/** 
 * Name operation utilities
 * Soppose we have a path -> "./a-level/main-level/1-level/1.txt"
 */
std::string getFiletype_FromPath(std::string path);
std::string getFilename_FromPath(std::string path);						// ret "1.txt"
std::string getFoldername_FromPath(std::string path);					// ret "./a-level/main-level/1-level"
std::string getRelativePath(std::string path, std::string basePath);	// ret "1-level"
																		// Yes, this func is stupid and will
																		// be modified soon

/**
 * Get all files in one directory by recusive way
 * @param targetName target directory name
 * @return a std::list of all files path
 */
std::list<std::string> walkDirectory(std::string targetName);


/*******************************************
 * Zip Ops (decompress and compress)
 *******************************************/

/**
 * Compress a directory to a zipfile
 * @param dirName directory need to be compressed
 * @param targetZipName zipfile's name
 * @return status 1 or 0 
 */
int compressDir(std::string dirName, std::string targetZipName);

/**
 * Uncompress a zip file to a target Directory
 * @param filename "THE" zip file
 * @param targetDirectory target path
 * @return status 0 or 1
 */
int uncompressFile(std::string filename, std::string targetDirectory);


/*******************************************
 * Patch Operations, IMPORTANT
 *******************************************/

/**
 * make a patch of two filename
 * @param filename1 old version file's name
 * @param filename2 new version file's name
 * @return QString type 
 */
QString makePatch_Files(char* filename1, char* filename2);

/**
 * make a unidiff patch of two filename
 * @param filename1 old version file's name
 * @param filename2 new version file's name
 * @return QString type 
 */
QString makePatch_Files_2(char* filename1, char* filename2);

/**
 * Store a patch entity to a file
 * @param patch QString type patch codes
 * @param filename patch file name
 * @return status value 0 or 1
 */
int storePatch(QString patch, char* filename);

/**
 * Get Patch of a directory, store it to a folder
 * @param directory1 old version directory
 * @param directory2 new version directroy
 * @return string of the path which stores patches
 */
std::string makePatch_Dirs(std::string directory1, std::string directory2);

/**
 * Get Patch of two zip files
 * @param zipfile1 old version zipfile
 * @param zipfile2 new version zipfile
 * @return string of where the patch zipfile is
 */
std::string makePatch_Zips(std::string zipfile1, std::string zipfile2);
