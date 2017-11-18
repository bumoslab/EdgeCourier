#include <sys/time.h>

#include "api.h"
#include "cmp.h"
#include "fm.h"


int main(int argc, char *argv[]){
	if(argc <=1){
		std::cout << "Error with argv" << std::endl;
		exit(0);
	}

	const char*	edgeip		= argv[1];
	const int	edgeport	= atoi(argv[2]);
	const char*	username	= argv[3];

	
	int edgesock = -1;
	edgesock = createUser((char*)edgeip, edgeport, (char*)username);
	filemanager fileManager = filemanager();

	/*************************************
	 * Create a socket to listen to proxy
	 *
	 * This socket should run all the time
	 *  but only within local loop network
	 *************************************/
	int sockfd, newsockfd, portno = 8001;
	char buffer[RECV_BUFF];
	struct sockaddr_in serv_addr, cli_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0){
		perror("Error opening socket");
		exit(1);
	}

	bzero((char*) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);
	if(bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
		perror("Error on bind");
		exit(2);
	}
	listen(sockfd, 10);
	/********************************
	 * Main Loop
	 * Dealing with proxy, I hate these codes much more than myself
	 * *****************************/
	socklen_t clilen = sizeof(cli_addr);
	while(1){
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
		if(newsockfd < 0){
			perror("Error on accept");
			exit(3);
		}

		memset(buffer, '\0', sizeof(buffer));
		std::cout << read(newsockfd, buffer, RECV_BUFF) << std::endl;
		std::string filename = std::string(buffer);
		{
			size_t p = filename.find_last_not_of(" \t\n");
			if(std::string::npos != p)
				filename.erase(p+1);
		}
		std::cout << "From Yongshu Bai: " << filename << std::endl; 
		filename = filename.substr(filename.rfind('/')+1);
		int exists = fileManager.exists(filename);
		if(exists == 1){
			std::cout << fileManager.getValue(filename) << " |  " << fileManager.getBackupPath(filename) << std::endl;

			struct timeval t1, t2;
			gettimeofday(&t1, NULL);
			
			std::string patch = makePatch_Zips(				\
					fileManager.getBackupPath(filename),	\
					fileManager.getValue(filename));

			gettimeofday(&t2, NULL);
			int milliSeconds = (t2.tv_sec - t1.tv_sec) * 1000 + (t2.tv_usec - t1.tv_usec)/1000;
			printf ("Diffs %d\n", milliSeconds);
			
			sendDelta((char*)edgeip, edgeport, (char*)username, \
					(char*)filename.c_str(), \
					(char*)"old.patch", \
					   (char*)patch.c_str(),\
					(char*)"Onedrive", (char*)"/");


			std::cout << fileManager.updateFile(filename, std::string("")) << std::endl;
			std::cout << "Finished Uploading" << std::endl;
			gettimeofday(&t1, NULL);
			milliSeconds = (t1.tv_sec - t2.tv_sec) * 1000 + (t1.tv_usec - t2.tv_usec)/1000;
			printf ("Trans %d\n", milliSeconds);
			write(newsockfd, "2", sizeof("2"));
		}
		else if(exists == 2){
			std::cout << "same file, no need to upload" << std::endl;
			write(newsockfd, "2", sizeof("2"));
		}else{
			std::string path = fileManager.addFile(filename, std::string(""));
			std::cout << path << std::endl;
			
			// Send this sync version file to edge.
			registerFile((char*)edgeip, edgeport, (char*)username, \
					(char*)filename.c_str(), (char*)path.c_str()); // Solve this location TODO
			std::cout << write(newsockfd, "2", sizeof("2")) << std::endl;
		}
		close(newsockfd);
	
	}

	// sock = createUser((char*)"10.32.135.251", 9999, (char*)"test");
	// sock = registerFile((char*)"10.32.135.251", 9999, (char*)"test", (char*)"1.docx", (char*)oldfile.c_str());
	// std::string patch = makePatch_Zips(oldfile, newfile);
	// sock = sendDelta((char*)"10.32.135.251", 9999, (char*)"test", (char*)"1.docx", (char*)"old.patch", (char*)patch.c_str(), (char*)"Onedrive", (char*)"/");
	// std::string code;
	// std::cout << "Input Code" <<std::endl;
	// std::cin >> code;
	// sock = getAuthCode((char*)"10.32.135.251", 9999, (char*)"test", code);
	// sock = sendDelta((char*)"10.32.135.251", 9999, (char*)"test", (char*)"1.docx", (char*)"old.patch", (char*)patch.c_str(), (char*)"Onedrive", (char*)"/");

	return 0;
}
