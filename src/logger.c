#include"socket.h"
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<unistd.h>
#include<fcntl.h>

struct node
{
	int port;
	char hostname[100];
	struct node* next;
};

struct node* addnode(struct node *data,int port,char *hostname)
{
	if(data==NULL)
	{
		data=(struct node*)malloc(sizeof(struct node));
		data->next=NULL;
		data->port=port;
		strcpy(data->hostname,hostname);
		return data;
	}
	struct node *temp=data;
	for(temp;temp->next!=NULL;temp=temp->next);
	temp->next=(struct node*)malloc(sizeof(struct node));
	temp=temp->next;
	temp->next=NULL;
	temp->port=port;
	strcpy(temp->hostname,hostname);
	return data;
}

void printlist(struct node *data)
{
	struct node *temp=data;
	for(temp;temp!=NULL;temp=temp->next)
		printf("%d %s\n",temp->port,temp->hostname);
}

struct node* delnode(struct node *data,int port,char *hostname)
{
	if(data==NULL)
	{
		strcpy(hostname,"dontknow");
		return NULL;
	}
	if(data->next==NULL)
	{
		if(data->port==port)
		{
			strcpy(hostname,data->hostname);
			free(data);
			return NULL;
		}
		else 
		{
			strcpy(hostname,"dontknow");
			return data;
		}
	}
	if(data->port==port)
	{
		strcpy(hostname,data->hostname);
		struct node *temp=data->next;
		free(data);
		return temp;
	}
	struct node *temp1=data,*temp2=data->next;
	for( ; temp2!=NULL ;temp2=temp2->next )
	{
		if(temp2->port==port)
		{
			strcpy(hostname,temp2->hostname);
			temp1->next=temp2->next;
			free(temp2);
			return data;
		}
		temp1=temp2;
	}
	strcpy(hostname,"dontknow");
	return data;
}

int getvalue(char *buffer,char *dest,char *key)
{
	char *ch=strstr(buffer,key);
	if(ch==NULL)
		return -1;
	ch=strstr(ch,"=");
	ch++;
	char *last=strstr(ch," ");
	int record=0;
	for(ch;ch<last;ch++)
	{
		dest[record]=*ch;
		record++;
	}
	dest[record]='\0';
	return 0;
}


int main()
{
	struct node *data=NULL;
	int sock2,clilen,clisock,port,fd,dnssock=socket(AF_INET,SOCK_DGRAM,0);
	struct sockaddr_in addr,cliaddr,dnsservaddr=createstructsockaddr_in(AF_INET,"127.0.0.1",54);
	char rule[500],fdbuffer[500],sock2buffer[100],hostname[100],databuffer[1000],*current=databuffer,tempdatabuffer[1000],portstring[20],tempname[100];
	fd_set rset;
	fd=open("/opt/proxifier/buffer/log",O_RDONLY);
	sock2=socket(AF_INET,SOCK_STREAM,0);
	listen(sock2,5);
	clilen=sizeof(addr);
	getsockname(sock2,(struct sockaddr*)&addr,&clilen);
	int port2=ntohs(addr.sin_port);
	sprintf(rule,"iptables -w -t nat -A OUTPUT -p tcp --dport 55 -j DNAT --to-destination 127.0.0.1:%d",port2);
	system(rule);
	clilen=sizeof(cliaddr);
	for( ; ; )
	{
		FD_ZERO(&rset);
		FD_SET(fd,&rset);
		FD_SET(sock2,&rset);
		select(max(fd,sock2)+1,&rset,NULL,NULL,NULL);
		if(FD_ISSET(fd,&rset))
		{
			int n=read(fd,fdbuffer,500);
			fdbuffer[n]='\0';
			strcpy(current,fdbuffer);
			for( ; ; )
			{
				if(strstr(databuffer,"\n")!=NULL)
				{
					int test1=getvalue(databuffer,hostname,"DST");
					int test2=getvalue(databuffer,portstring,"SPT");
					strcpy(tempdatabuffer,strstr(databuffer,"\n")+1);
					strcpy(databuffer,tempdatabuffer);
					if(test1!=-1&&test2!=-1)
					{
						port=atoi(portstring);
						bzero(&tempname,100);
						sendto(dnssock,hostname,strlen(hostname),0,(struct sockaddr*)&dnsservaddr,sizeof(dnsservaddr));
						recvfrom(dnssock,tempname,100,0,NULL,NULL);
						if(strcmp(tempname,"0")!=0)
						{
							strcpy(hostname,tempname);
						}
						data=addnode(data,port,hostname);
					}
				}
				else
					break;
			}
			current=databuffer+strlen(databuffer);
		}
		else if(FD_ISSET(sock2,&rset))
		{
			clisock=accept(sock2,(struct sockaddr*)&cliaddr,&clilen);
			int n=read(clisock,sock2buffer,100);
			if(n<=0)
			{
				close(clisock);
				continue;
			}
			sock2buffer[n]='\0';
			port=atoi(sock2buffer);
			data=delnode(data,port,hostname);
			write(clisock,hostname,strlen(hostname));
			close(clisock);
		}


	}
	return 0;
}


