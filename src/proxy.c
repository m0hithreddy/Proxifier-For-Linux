#include"proxy.h"
#include<string.h>
#include<stdlib.h>
#include<stdio.h>

int getproxyserverip(char *fileinstring,char *proxyip)
{
	FILE *fp=fopen(fileinstring,"r");
	char buffer[100],*counterpointer;
	counterpointer=fgets(buffer,99,fp);
	while(counterpointer!=NULL)
	{
		if(strstr(buffer,"ProxyServerIP")!=NULL)
		{
			char *temp=strstr(buffer,"=");
			temp++;
			temp[strlen(temp)-1]='\0';
			strcpy(proxyip,temp);
			break;
		}
		counterpointer=fgets(buffer,99,fp);
	}
	if(strlen(proxyip)==0)
	{
		printf("ProxyServerIP is wrongly configured in %s\n",fileinstring);
		exit(-1);
	}
	return 0;
}

int getproxyserverport(char *fileinstring)
{
	int port;
	FILE *fp=fopen(fileinstring,"r");
	char buffer[100],portinstring[10],*counterpointer;
	bzero(&portinstring,10);
	counterpointer=fgets(buffer,99,fp);
	while(counterpointer!=NULL)
	{
		if(strstr(buffer,"ProxyServerPort")!=NULL)
		{
			char *temp=strstr(buffer,"=");
			temp++;
			temp[strlen(temp)-1]='\0';
			strcpy(portinstring,temp);
			break;
		}
		counterpointer=fgets(buffer,99,fp);
	}
	if(strlen(portinstring)==0)
	{
		printf("ProxyServerPort is wrongly configured in %s\n",fileinstring);
		exit(-1);
	}
	else
		port=atoi(portinstring);
	return port;
}

int getproxyserverauthorization(char *fileinstring,char *proxypass)
{
	FILE *fp=fopen(fileinstring,"r");
	char buffer[100],*counterpointer;
	counterpointer=fgets(buffer,99,fp);
	while(counterpointer!=NULL)
	{
		if(strstr(buffer,"ProxyServerAuthorization")!=NULL)
		{
			char *temp=strstr(buffer,"=");
			temp++;
			temp[strlen(temp)-1]='\0';
			strcpy(proxypass,temp);
			break;
		}
		counterpointer=fgets(buffer,99,fp);
	}
	return 0; 
}
