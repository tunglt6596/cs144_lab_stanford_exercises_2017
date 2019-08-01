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
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(8080);
	servaddr.sin_addr.s_addr = inet_addr("184.72.104.217");
	bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
	
	struct sockaddr_in cliaddr;
	bzero(&cliaddr, sizeof(cliaddr));
	cliaddr.sin_family = AF_INET;
	cliaddr.sin_port = htons(1024);
	cliaddr.sin_addr.s_addr = inet_addr("184.72.104.221");
	connect(sockfd, (struct sockaddr*)&cliaddr, sizeof (cliaddr));
	
	char buffer[1024];
	memset(buffer, 0, sizeof(buffer));
	read(sockfd, buffer, sizeof(buffer));
	printf("%s", buffer);	
	close(sockfd);			
	return 0;
}
