#include"socket.h"
#include<stdio.h> 
#include<stdlib.h>
#include<string.h>
#include<netinet/in.h>
#include<unistd.h>
#include<sys/wait.h>
#include<sys/types.h>

int main(int argc,char **argv)
{
	int sockfd,len,proxyserverport,connfd,spt;
	char proxyserverip[20],pass64[200],rule[500],buffer[500],hostname[100],portstring[20];
	struct sockaddr_in servaddr,cliaddr,hostaddr=createstructsockaddr_in(AF_INET,"127.0.0.1",55);
	bzero(&proxyserverip,20);
	bzero(&pass64,200);
	sockfd=socket(AF_INET,SOCK_STREAM,0);
	listen(sockfd,25);
	len=sizeof(servaddr);
	getsockname(sockfd,(struct sockaddr*)&servaddr,&len);
	strcpy(proxyserverip,argv[1]);
	proxyserverport=atoi(argv[2]);
	if(strcmp(argv[3],"0")!=0)
	{
		strcpy(pass64,argv[3]);
	}
	sprintf(rule,"iptables -w -t nat -A OUTPUT -p tcp --tcp-flags ALL SYN ! -d %s --dport 80 -j LOG --log-prefix \"OUTPUT-PACKETS80: \" ",proxyserverip);
	system(rule);
	sprintf(rule,"iptables -w -t nat -A OUTPUT -p tcp ! -d %s --dport 80 -j DNAT --to-destination 127.0.0.1:%d",proxyserverip,ntohs(servaddr.sin_port));
	system(rule);
	len=sizeof(cliaddr);
	for( ; ; )
	{
		connfd=accept(sockfd,(struct sockaddr*)&cliaddr,&len);
		spt=ntohs(cliaddr.sin_port);
		sprintf(portstring,"%d",spt);
		strcpy(hostname,"dontknow");
		if(fork()==0)
		{
			if(fork()==0)
			{
				fd_set listenset;
				int proxysock=socket(AF_INET,SOCK_STREAM,0),n;
				char serverdata[65535],clidata[65535],modclidata[65535];
				struct sockaddr_in proxyservaddr;
				bzero(&modclidata,65535);
				bzero(&clidata,65535);
				bzero(&serverdata,65535);
				proxyservaddr=createstructsockaddr_in(AF_INET,proxyserverip,proxyserverport);
				for(int i=1;i<=5;i++)
				{
					int hostsock=socket(AF_INET,SOCK_STREAM,0);
					if(connect(hostsock,(struct sockaddr*)&hostaddr,sizeof(hostaddr))!=0)
					{
						close(hostsock);
						sleep(1);
						continue;
					}
					write(hostsock,portstring,strlen(portstring));
					int n=read(hostsock,hostname,100);
					if(n<=0)
					{
						close(hostsock);
						sleep(1);
						continue;
					}
					hostname[n]='\0';
					if(strcmp(hostname,"dontknow")==0)
					{
						close(hostsock);
						sleep(1);
						continue;
					}
					close(hostsock);
					break;
				}
				if(strcmp(hostname,"dontknow")==0)
				{
					close(connfd);
					exit(0);
				}
				if(connect(proxysock,(struct sockaddr*)&proxyservaddr,sizeof(proxyservaddr))!=0)
				{
					exit(-1);
				}
				for( ; ; )
				{
					FD_ZERO(&listenset);
					FD_SET(connfd,&listenset);
					FD_SET(proxysock,&listenset);
					select(max(connfd,proxysock)+1,&listenset,NULL,NULL,NULL);
					if(FD_ISSET(connfd,&listenset))
					{
						bzero(&clidata,sizeof(clidata));
						n=read(connfd,clidata,65535);
						if(n<=0)
						{
							exit(0);
						}
						if(strncmp(clidata,"GET",3)==0)
						{
							strcat(modclidata,"GET http://");
							strcat(modclidata,hostname);
							strncat(modclidata,strstr(clidata," ")+1,strlen(strstr(clidata," ")+1)-strlen(strstr(clidata,"\r\n\r\n")));
							strcat(modclidata,"\r\nProxy-Connection: keep-alive\r\n");
							if(strlen(pass64)!=0)
							{
								strcat(modclidata,"Proxy-Authorization: Basic ");
								strcat(modclidata,pass64);
							}
							strcat(modclidata,"\r\n\r\n");
						}
						else if(strncmp(clidata,"POST",4)==0)
						{
							strcat(modclidata,"POST http://");
							strcat(modclidata,hostname);
							char *last=strstr(clidata,"\r\n\r\n");
							strncat(modclidata,strstr(clidata," ")+1,strlen(strstr(clidata," ")+1)-strlen(last));
							strcat(modclidata,"\r\nProxy-Connection: keep-alive");
							if(strlen(pass64)!=0)
							{
								strcat(modclidata,"\r\nProxy-Authorization: Basic ");
								strcat(modclidata,pass64);
							}
							strcat(modclidata,last);
						}
						write(proxysock,modclidata,strlen(modclidata));
					}
					else if(FD_ISSET(proxysock,&listenset))
					{
						bzero(&serverdata,sizeof(serverdata));
						n=read(proxysock,serverdata,65535);
						if(n<=0)
						{
							exit(0);
						}
						write(connfd,serverdata,n);
					}
				}
				exit(0);
			}
			exit(0);
		}
		wait(NULL);
		close(connfd);
	}
	return 0;
}
