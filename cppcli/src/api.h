#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>


#define SEND_BUFF 128 
#define RECV_BUFF 128


/**
 * Create A User space at edge
 * @param ip_addr Edge IP
 * @param port Edge port
 * @param username 'THE' username
 */
int createUser(char* ip_addr, int port, char* username);

/**
 * Register a File on edge server when file add to watch list
 * @param ip_addr Edge IP
 * @param port Edge port
 * @param username User's name
 * @param filename New filename
 * @param filepath the path of uploading file
 * @return status code 1 or 0
 */
int registerFile(char* ip_addr, int port, char* username, \
					char* filename, char* filepath);

/**
 * Send the Delta file to edge and let it upload
 * @param ip_addr Edge IP
 * @param port Edge port
 * @param username User's name
 * @param filename The file that need to be delta sync
 * @param deltaname The patch file name
 * @param deltafile The path of the patch file
 * @param targetService The cloud service for edge to use
 * @param cloudpath The path that might needed for uploading
 * @return status code 1 or 0
 */
int sendDelta(char* ip_addr, int port, char* username, \
					char* filename,char* deltaname, char* deltafile, \
					char* targetService, char* cloudpath);


std::string getCode_FromClient(int port);

int getAuthCode(int sock, std::string code);

int fileExist(std::string filename);
