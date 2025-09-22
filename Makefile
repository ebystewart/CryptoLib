CC=gcc
CFLAGS=-g
LIBS=
OBJS= aes.o	\
	rand.o \
	rsa.o \
	test.o \
	sha2.o \
	math.o	

CryptoLib.bin:${OBJS}
	${CC} ${CFLAGS} ${OBJS} -o CryptoLib.bin

aes.o:aes.c
	${CC} ${CFLAGS} -c aes.c -I . -o aes.o

rsa.o:rsa.c
	${CC} ${CFLAGS} -c rsa.c -I . -o rsa.o

rand.o:rand.c
	${CC} ${CFLAGS} -c rand.c -I . -o rand.o

test.o:test.c
	${CC} ${CFLAGS} -c test.c -I . -o test.o

sha2.o:sha2.c
	${CC} ${CFLAGS} -c sha2.c -I . -o sha2.o

sha3.o:sha3.c
	${CC} ${CFLAGS} -c sha3.c -I . -o sha3.o

math.o:math.c
	${CC} ${CFLAGS} -c math.c -I . -o math.o


all:
	make

clean:
	rm *.o
	rm *.bin