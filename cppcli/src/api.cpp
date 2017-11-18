#include "api.h"
#include "cmp.h"


int createUser(char* ip_addr, int port, char* username){
	std::cout << ip_addr << port << username << std::endl;
	int sock = 0;
	struct sockaddr_in serv_addr;
	char buffer[SEND_BUFF] = {0};
	sprintf(buffer, "{'op':1,'user':'%s'}", username);
	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		printf("\n Socket creation error\n");
		return -1;
	}

	memset(&serv_addr, '0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	if(inet_pton(AF_INET, ip_addr, &serv_addr.sin_addr)<=0) 
	{
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		printf("\nConnection Failed \n");
		return -1;
	}
	send(sock , buffer , sizeof(buffer) , 0 );
	printf("%s\n",buffer );
	std::string code = getCode_FromClient(7999);
	memset(buffer, '\0', SEND_BUFF);
	sprintf(buffer, "%s", code.c_str());
	send(sock , buffer , sizeof(buffer) , 0 );
	close(sock);
	return 0;
}



int registerFile(char* ip_addr, int port, char* username, char* filename, char* filepath){
	int sock = 0;
	struct sockaddr_in serv_addr;
	char buffer[SEND_BUFF] = {0};
	sprintf(buffer, "{'op':2,'user':'%s','filename':'%s'}", username, filename);
	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		printf("\n Socket creation error\n");
		return -1;
	}

	memset(&serv_addr, '0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	if(inet_pton(AF_INET, ip_addr, &serv_addr.sin_addr)<=0)
	{
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		printf("\nConnection Failed \n");
		return -1;
	}
	send(sock , buffer , sizeof(buffer) , 0 );
	printf("%s\n",buffer );
	FILE* f = fopen(filepath, "rb");
	if (f == NULL){
		printf("File %s doesn't exist:%s\n", filename, filepath);
	}

	// Reset Buffer for file transport
	memset(buffer, '\0', sizeof(buffer));

	while(fread(buffer, 1, SEND_BUFF, f) > 0){
		// printf("------------\n%s\n^^^^^^^^^^^^^\n\n", buffer);
		send(sock , buffer , sizeof(buffer), 0);
		memset(buffer, '\0', sizeof(buffer));
		if (feof(f)){
			break;
		}
	}

	close(sock);
	return 0;


}


int sendDelta(char* ip_addr, int port, char* username, char* filename,char* deltaname, char* deltafile, char* targetService, char* cloudpath){
	int sock = 0;
	struct sockaddr_in serv_addr;
	char buffer[SEND_BUFF] = {0};
	int traffic = 0;
	if(!strcmp(targetService, "Onedrive"))
		perror("[SendDelta]\tNot Onedrive");
	if(!strcmp(cloudpath, "/"))
		perror("[SendDelta]\tNot on root ID");

	sprintf(buffer, "{'op':3,'user':'%s','filename':'%s','deltaname':'%s'}", username, filename, deltaname);
	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		printf("\n Socket creation error\n");
		return -1;
	}

	memset(&serv_addr, '0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	if(inet_pton(AF_INET, ip_addr, &serv_addr.sin_addr)<=0)
	{
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		printf("\nConnection Failed \n");
		return -1;
	}
	traffic += send(sock , buffer , sizeof(buffer) , 0 );
	printf("%s\n",buffer );
	FILE* f = fopen(deltafile, "rb");
	if (f == NULL){
		printf("File %s doesn't exist:%s\n", deltaname, deltafile);
	}

	// Reset Buffer for file transport
	memset(buffer, '\0', sizeof(buffer));

	while(fread(buffer, 1, SEND_BUFF, f) > 0){
		// printf("------------\n%s\n^^^^^^^^^^^^^\n\n", buffer);
		traffic += send(sock , buffer , sizeof(buffer), 0);
		memset(buffer, '\0', sizeof(buffer));
		if (feof(f)){
			break;
		}
	}
	traffic += send(sock, "1", 1, 0);

	// Get Response
	memset(buffer, '\0', sizeof(buffer));
	traffic += recv(sock , buffer , sizeof(buffer), 0);
	int ret = -1;
response:
	ret = atoi(buffer);
	if(ret == 0){
		std::cout << "Upload File Failed" <<std::endl;
	}else if(ret == 1){
		std::cout << "Upload File Sucessful" <<std::endl;
	}else if(ret == 2){
		std::cout << "Code Needed" <<std::endl;
		std::string code;
		// std::cout << "Input Code" <<std::endl;
		// std::cin >> code;
		code = getCode_FromClient(7999);
		traffic += getAuthCode(sock, code);
		memset(buffer, '\0', sizeof(buffer));
		while(1){
			traffic += recv(sock , buffer , sizeof(buffer), 0);
			if(strlen(buffer)!=0){
				// std::cout << strlen(buffer) << std::endl;
				break;
			}
		}
		goto response;
	}else{
		std::cout << "God know what happened" <<std::endl;
	}

	std::cout << "Traffic " << traffic << std::endl;
	close(sock);
	return 0;
}

std::string getCode_FromClient(int port){
	int sock = 0;
	struct sockaddr_in serv_addr;
	char buffer[RECV_BUFF] = {0};
	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		printf("\n Socket creation error\n");
		return std::string();
	}

	memset(&serv_addr, '0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) 
	{
		printf("\nInvalid address/ Address not supported \n");
		return std::string();
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		printf("\nConnection Failed \n");
		return std::string();
	}
	send(sock , "I need code!" , 128 , 0 );
	recv(sock, buffer, sizeof(buffer), 0);
	printf("Code From XinZhang: %s\n",buffer );
	std::string str = std::string(buffer);
	str = str.substr(str.rfind('=')+1);
	close(sock);
	return str;

}

int getAuthCode(int sock, std::string code){
	char buffer[SEND_BUFF] = {0};
	int traffic = 0;
	strcpy(buffer, code.c_str());
	traffic += send(sock , buffer , sizeof(buffer) , 0 );
	printf("%s\n",buffer );
	close(sock);
	return traffic;
}
