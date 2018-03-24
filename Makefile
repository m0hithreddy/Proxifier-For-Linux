C_FILES=$(wildcard *.c)

OBJ_FILES=${C_FILES:.c=.o}

all:fakehttpserver fakehttpsserver fakednsserver proxifier logger ${OBJ_FILES}

fakehttpserver:${OBJ_FILES}
	gcc fakehttpserver.o socket.o -o executables/fakehttpserver

fakehttpsserver:${OBJ_FILES}
	gcc fakehttpsserver.o socket.o -o executables/fakehttpsserver

proxifier:${OBJ_FILES}
	gcc proxifier.o proxy.o base64.o -o executables/proxifier

logger:${OBJ_FILES}
	gcc logger.o socket.c -o executables/logger

fakednsserver:${OBJ_FILES}
	gcc fakednsserver.o socket.o -o executables/fakednsserver

%.o : %.c
	gcc -c $< -o $@

install:
	sh install.sh

clean:
	rm -rf *.o executables/*

uninstall:
	rm -rf /opt/proxifier /usr/local/bin/proxifier

