CFLAGS=-O0 -g3 -Wall

.PHONY: all clean

all: mkey sync newsync pem

mkey: mkey.c
	gcc ${CFLAGS} mkey.c `xml2-config --cflags` `xml2-config --libs` -lccn -lcrypto -o mkey

sync: sync.c
	gcc ${CFLAGS} sync.c -lccn -lcrypto -o sync

newsync: newsync.c
	gcc ${CFLAGS} newsync.c -lccn -lcrypto -o newsync

pem: pem.c
	gcc ${CFLAGS} pem.c -lcrypto -o pem

clean:
	rm -rf mkey sync newsync pem
