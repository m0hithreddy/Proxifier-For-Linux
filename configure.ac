
# Initate the Proxifier-For-Linux configure file

AC_INIT(Proxifier-For-Linux, [1.0], , , [https://github.com/m0hithreddy/Proxifier-For-Linux])

# Scripts install directory 

AC_CONFIG_AUX_DIR([build-aux])

# Saftey to check to verify src directory is sane 

AC_CONFIG_SRCDIR([src/proxifier.c])

AC_CHECK_FILES(
[${srcdir}/src/proxifier.c
${srcdir}/src/proxy_http.c
${srcdir}/src/proxy_https.c
${srcdir}/src/proxy_dns.c
${srcdir}/src/logger.c
${srcdir}/src/proxy.c
${srcdir}/src/proxy.h
${srcdir}/src/socket.c
${srcdir}/src/socket.h
${srcdir}/src/base64.c
${srcdir}/src/base64.h],
[],
[AC_MSG_ERROR([Repository corrupted, redownload the source.])]
)

# Programs required for build

AC_PROG_CC

AC_PROG_INSTALL

# Some predefined header checks

AC_FUNC_MALLOC

# Checks for system headers

AC_CHECK_HEADERS(
[stdio.h \
stdlib.h], 
[],
[AC_MSG_ERROR([${ac_header} is required but not found. Headers provided by libc, installed by default in all distributions.])]
)

# Checks for system funcs

AC_CHECK_FUNCS(
[printf \
strcmp],
[],
[AC_MSG_ERROR([${ac_func} is required but not found. Should be included in libc, check the libc variant installed in your system.])]
)

# Checks for system symbols

AC_CHECK_DECLS(
[NULL,
LONG_MAX],
[],
[AC_MSG_ERROR([Symbol required but not found. Should be included in libc, check the libc variant installed in your system.])],
[[#include<stddef.h>
#include<limits.h>]]
)

# Make Makefile 

AM_INIT_AUTOMAKE([subdir-objects])

AC_CONFIG_FILES([Makefile])

# Make config.h header file 

AC_CONFIG_HEADERS([config.h])

# Conclude configure

AC_OUTPUT

