#include <netinet/in.h>
#include <strings.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/errno.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in cliaddr;
	bzero(&cliaddr, sizeof(cliaddr));
	cliaddr.sin_family = AF_INET;
	cliaddr.sin_port = htons(10002);
	cliaddr.sin_addr.s_addr = inet_addr("10.0.1.100");
	bind(sockfd, (struct sockaddr *)&cliaddr, sizeof(struct sockaddr));
	
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(80);
	servaddr.sin_addr.s_addr = inet_addr("184.72.104.217");
	connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));	
	char data[1024];
	memset(data, 0, sizeof(data));	
	char* httpget = "GET / HTTP/1.1\r\n\r\n";
	write(sockfd, httpget, strlen(httpget));	
	read(sockfd, data, sizeof(data));
	printf("%s", data);	
	return 0;
}
