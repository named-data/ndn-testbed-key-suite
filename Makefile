CFLAGS=-O0 -g3 -Wall

.PHONY: all clean

all: pem

pem: pem.c
	gcc ${CFLAGS} pem.c -lcrypto -o pem

clean:
	rm -rf pem *.dSYM
