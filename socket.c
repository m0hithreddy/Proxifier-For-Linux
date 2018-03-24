#include"socket.h"
#include<string.h>
#include<netinet/in.h>
#include<sys/socket.h>
#include<arpa/inet.h>

int max(int a,int b)
{
	if(a>b)
		return a;
	else 
		return b;
}

struct sockaddr_in createstructsockaddr_in(int family,char* ipv4,int port)
{
	struct sockaddr_in servaddr;
	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_port=htons(port);
	if ( strcmp(ipv4,"0.0.0.0")!=0 )
	{
		inet_aton(ipv4,&servaddr.sin_addr);
	}
	else 
	{
		servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	}
	return servaddr;
}

int createsocket(int family,int type,char *ipv4,int port)
{	int sockfd=socket(family,type,0);
	struct sockaddr_in servaddr;
	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family=family;
	servaddr.sin_port=htons(port);
	inet_aton(ipv4,&servaddr.sin_addr);
	if ( bind(sockfd,(struct sockaddr*)&servaddr,sizeof(servaddr))!=0)
		return -1;
	return sockfd;
}

