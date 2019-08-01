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
	cliaddr.sin_port = htons(10003);
	cliaddr.sin_addr.s_addr = inet_addr("10.0.1.100");
	bind(sockfd, (struct sockaddr*)&cliaddr, sizeof(cliaddr));
	
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(8080);
	servaddr.sin_addr.s_addr = inet_addr("184.72.104.217");
	connect(sockfd, (struct sockaddr*)&servaddr, sizeof (servaddr));
	
	char *welcome = "Hello server!!!";
	write(sockfd, welcome, strlen(welcome));
	close(sockfd);		
	return 0;
}
