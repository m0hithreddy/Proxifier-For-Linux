
# Initate the Proxifier-For-Linux configure file

AC_INIT(Proxifier-For-Linux, [1.0], , , [https://github.com/m0hithreddy/Proxifier-For-Linux])

# Scripts install directory 

AC_CONFIG_AUX_DIR([build-aux])

# Saftey checks to verify whether src directory is sane 

AC_CONFIG_SRCDIR([src/proxifier.c])

AC_CHECK_FILES(
[${srcdir}/src/proxifier.c
${srcdir}/src/proxifier.h
${srcdir}/src/proxy.c
${srcdir}/src/proxy.h
${srcdir}/src/proxy_http.c
${srcdir}/src/proxy_http.h
${srcdir}/src/proxy_socket.c
${srcdir}/src/proxy_socket.h
${srcdir}/src/proxy_structures.c
${srcdir}/src/proxy_structures.h
${srcdir}/src/proxy_functions.c
${srcdir}/src/proxy_functions.h
${srcdir}/src/proxy_configuration.c
${srcdir}/src/proxy_configuration.h
${srcdir}/src/proxy_dns.c
${srcdir}/src/proxy_dns.h
${srcdir}/src/http.c
${srcdir}/src/http.h
${srcdir}/src/dns.c
${srcdir}/src/dns.h
${srcdir}/src/bit.c
${srcdir}/src/bit.h
${srcdir}/src/base64.c
${srcdir}/src/base64.h
${srcdir}/src/firewall.c
${srcdir}/src/firewall.h
${srcdir}/proxifier.conf],
[],
[AC_MSG_ERROR([Repository corrupted, redownload the source.])]
)

# Programs required for build

AC_PROG_CC

AC_PROG_INSTALL

AC_PROG_SED

# Some predefined header checks

AC_FUNC_MALLOC

# Checks for system headers

AC_CHECK_HEADERS(
[stdio.h \
stdlib.h \
string.h \
stddef.h \
stdint.h \
stdbool.h \
stdarg.h \
errno.h \
fcntl.h \
unistd.h \
signal.h \
limits.h \
netdb.h \
sys/socket.h \
sys/types.h \
sys/select.h \
sys/time.h \
sys/signalfd.h \
sys/wait.h \
netinet/in.h \
netinet/tcp.h \
arpa/inet.h \
linux/netfilter_ipv4.h], 
[],
[AC_MSG_ERROR([${ac_header} is required but not found. Headers provided by libc, installed by default in all distributions.])]
)

# Checks for system funcs

AC_CHECK_FUNCS(
[printf \
atol \
exit \
fopen \
read \
strcmp \
strlen \
strstr \
strcasestr \
strncpy \
strncasecmp \
strcasecmp \
strdup \
execlp \
sigaddset \
sigemptyset \
sigwait \
fork \
waitpid \
memcpy \
malloc \
calloc \
memset \
fcntl \
signalfd \
select \
close \
recvfrom \
sendto \
memmem \
accept \
getsockopt \
inet_ntop \
snprintf \
htons \
htonl \
atoi \
free \
getaddrinfo \
socket \
bind \
getsockname \
listen \
connect \
write],
[],
[AC_MSG_ERROR([${ac_func} is required but not found. Should be included in libc, check the libc variant installed in your system.])]
)

#Checks for optional system functions

AC_CHECK_FUNCS(
[memndup],
[],
[] 
)

# Checks for system symbols

AC_CHECK_DECLS(
[NULL,
LONG_MAX,
WIFEXITED,
WEXITSTATUS,
SIGCHLD,
SIGPIPE,
SIGRTMIN,
SIGTERM,
SIGINT,
SIG_BLOCK,
SOCK_DGRAM,
F_SETFL,
F_GETFL,
O_NONBLOCK,
FD_ZERO,
FD_SET,
FD_ISSET,
EINTR,
EAGAIN,
EWOULDBLOCK,
AI_PASSIVE,
SOL_IP,
SO_ORIGINAL_DST,
AF_INET,
INET_ADDRSTRLEN,
INET6_ADDRSTRLEN,
AF_INET6,
SOCK_STREAM,
EFAULT,
INADDR_LOOPBACK],
[],
[AC_MSG_ERROR([Symbol required but not found. Should be included in libc, check the libc variant installed in your system.])],
[[#include<stddef.h>
#include<limits.h>
#include<signal.h>
#include<fcntl.h>
#include<errno.h>
#include<sys/wait.h>
#include<sys/socket.h>
#include<netdb.h>
#include<linux/netfilter_ipv4.h>]]
)

# Pthread library checks

AC_CHECK_LIB(pthread, pthread_create, [], [AC_MSG_ERROR([-lpthread is required but not found. Installed by default in all distributions])])

AC_CHECK_FUNCS(
[pthread_create \
pthread_join \
pthread_mutex_init \
pthread_mutex_lock \
pthread_mutex_unlock \
pthread_mutex_destroy \
pthread_kill \
pthread_sigmask],
[],
[AC_MSG_ERROR([${ac_func} required but not found. Function provided by libpthread, installed by default in all distributions])]
)

# Make Makefile 

AM_INIT_AUTOMAKE([subdir-objects])

AC_CONFIG_FILES([Makefile])

# Make config.h header file 

AC_CONFIG_HEADERS([config.h])

# Conclude configure

AC_OUTPUT

