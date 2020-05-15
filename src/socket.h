#include<netinet/in.h>

struct sockaddr_in createstructsockaddr_in(int family,char* ipv4,int port);
int createsocket(int family,int type,char *ipv4,int port);
int max(int a,int b);
