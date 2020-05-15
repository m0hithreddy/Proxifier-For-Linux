#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"proxy.h"
#include"base64.h"
int main(int argc,char **argv)
{
	if(argc==1 || argc>3)
	{
		printf("Usage--->proxifier <start/stop> <ConfigurationFileNo>\n<start/stop>Start Option starts the proxifier and Stop stops the proxifier\n<ConfigurationFileNo>If ConfigurationFileNo when specified n it loads information from proxifier.conf.n when  not specified it loads the information from proxifier.conf file\n");
	       exit(0);
	}	       
	if(strcmp(argv[1],"start")==0)
	{
		int proxyserverport;
		char command[300],file[40],proxyserverip[20],pass[100],pass64[100];
		bzero(&pass,sizeof(pass));
		bzero(&pass64,sizeof(pass64));
		system("killall fakednsserver 1>/dev/null 2>/dev/null");
		system("killall fakehttpserver 1>/dev/null 2>/dev/null");
		system("killall fakehttpsserver 1>/dev/null 2>/dev/null");
		system("killall logger 1>/dev/null 2>/dev/null");
		system("killall dmesg 1>/dev/null 2>/dev/null");
		//system("kill `ps -a -o pid,command | grep 'dmesg -w' | tr ' ' '^'| cut -d '^' -f 1` 1>/dev/null 2>/dev/null");
		printf("**********************************************************************\n\n");
		printf("PROXIFIER by MOHITH REDDY\n\n");
		printf("Configuring System......\n\n");
		if(argc==3)
		{
			sprintf(file,"/opt/proxifier/conf/proxifier.conf.%s",argv[2]);
			FILE *fp=fopen(file,"r");
			if(fp==NULL)
			{
				printf("File /opt/proxifier/conf/proxifier.conf.%s is not found configure it to run this application\nConfigure as follow,\nProxyServerIP=<ipaddress of proxy server>\nProxyServerPort=<port on which proxy service is running>\nProxyServerAuthorization=<username>:<pass>\n",argv[2]);
				exit(-1);
			}
			fclose(fp);
		}
		else 
		{
			sprintf(file,"/opt/proxifier/conf/proxifier.conf");
			FILE *fp=fopen(file,"r");
			if(fp==NULL)
			{
				printf("File /opt/proxifier/conf/proxifier.conf is not found configure it to run this application\nConfigure as follow,\nProxyServerIP=<ipaddress of proxy server>\nProxyServerPort=<port on which proxy service is running>\nProxyServerAuthorization=<username>:<pass>\n");
				exit(-1);
			}
			fclose(fp);
		}
		proxyserverport=getproxyserverport(file);
		getproxyserverip(file,proxyserverip);
		getproxyserverauthorization(file,pass);
		if(strlen(pass)!=0)
			encodepass(pass,pass64);
		else
			strcpy(pass64,"0");
		//system("cp /etc/resolv.conf /opt/proxifier/bak/resolv.conf.bak");
		system("iptables -w -t nat -F");
		system("rm -rf /opt/proxifier/buffer/log");
		system("mkfifo /opt/proxifier/buffer/log");
		system("dmesg -C");
		system("dmesg -w >/opt/proxifier/buffer/log &");
		printf("Running a local HTTP SERVER......\n\n");
		sprintf(command,"/opt/proxifier/bin/fakehttpserver %s %d %s &",proxyserverip,proxyserverport,pass64);
		system(command);
		printf("RUNNING a local HTTPS SERVER......\n\n");
		sprintf(command,"/opt/proxifier/bin/fakehttpsserver %s %d %s &",proxyserverip,proxyserverport,pass64);
		system(command);
		printf("Running a local DNS SERVER.......\n\n");
		system("/opt/proxifier/bin/fakednsserver &");
		printf("Running Packet Logger\n\n");
		system("/opt/proxifier/bin/logger &");
		printf("**********************************************************************\n\n");
	}
	else if(strcmp(argv[1],"stop")==0)
	{
		printf("\nReverting back the system....\n\n");
		system("iptables -w -t nat -F");
		system("killall fakednsserver 1>/dev/null 2>/dev/null");
		system("killall fakehttpserver 1>/dev/null 2>/dev/null");
		system("killall fakehttpsserver 1>/dev/null 2>/dev/null");
		system("killall logger 1>/dev/null 2>/dev/null");
		system("killall dmesg 1>/dev/null 2>/dev/null");
		//system("kill `ps -a -o pid,command | grep 'dmesg -w' | tr ' ' '^'| cut -d '^' -f 1` 1>/dev/null 2>/dev/null");
		//system("cp /opt/proxifier/bak/resolv.conf.bak /etc/resolv.conf");
	}
	else
	{
		printf("Usage--->proxifier <start/stop> <ConfigurationFIleNo>\nStart Option starts the proxifier and Stop stops the proxifier\nIf ConfigurationFileNo when specified n it loads information from proxifier.conf.n when is is not specified loads the information from proxifier.conf file\n");
	}
	return 0; 
}
