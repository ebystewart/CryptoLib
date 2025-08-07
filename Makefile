CC=gcc
CFLAGS=-g
LIBS=
OBJS= aes.o	\
	test.o	

CryptoLib.bin:${OBJS}
	${CC} ${CFLAGS} ${OBJS} -o CryptoLib.bin

aes.o:aes.c
	${CC} ${CFLAGS} -c aes.c -I . -o aes.o

test.o:test.c
	${CC} ${CFLAGS} -c test.c -I . -o test.o


all:
	make

clean:
	rm *.o
	rm *.bin