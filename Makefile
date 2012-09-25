CFLAGS=-O0 -g3 -Wall

.PHONY: all clean

all: mkey pem

mkey: mkey.c
	gcc ${CFLAGS} mkey.c `xml2-config --cflags` `xml2-config --libs` -lccn -lccnsync -lcrypto -o mkey

pem: pem.c
	gcc ${CFLAGS} pem.c -lcrypto -o pem

clean:
	rm -rf mkey pem
