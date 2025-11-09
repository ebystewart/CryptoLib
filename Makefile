CC=gcc
CFLAGS=-g
LIBS=
OBJS= aes.o	\
	rand.o \
	rsa.o \
	test.o \
	sha2.o \
	sha3.o \
	math.o \
	ecc.o 	\
	ecdh.o 	\
	ecdsa.o	\
	chacha20.o	\
	poly1305.o	\
	aead.o	\
	tls12.o	\
	tls13.o	\
	tls13_sm.o

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

ecc.o:ecc.c
	${CC} ${CFLAGS} -c ecc.c -I . -o ecc.o

ecdh.o:ecdh.c
	${CC} ${CFLAGS} -c ecdh.c -I . -o ecdh.o

ecdsa.o:ecdsa.c
	${CC} ${CFLAGS} -c ecdsa.c -I . -o ecdsa.o

chach20.o:chacha20.c
	${CC} ${CFLAGS} -c chacha20.c -I . -o chacha20.o

poly1305.o:poly1305.c
	${CC} ${CFLAGS} -c poly1305.c -I . -o poly1305.o

aead.o:aead.c
	${CC} ${CFLAGS} -c aead.c -I . -o aead.o

tls12.o:tls12.c
	${CC} ${CFLAGS} -c tls12.c -I . -o tls12.o

tls13.o:tls13.c
	${CC} ${CFLAGS} -c tls13.c -I . -o tls13.o

tls13_sm.o:tls13_sm.c
	${CC} ${CFLAGS} -c tls13_sm.c -I . -o tls13_sm.o

all:
	make

clean:
	rm *.o
	rm *.bin