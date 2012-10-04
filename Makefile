CFLAGS=-O0 -g3 -Wall

.PHONY: all clean

all: mkey

mkey: mkey.c
	gcc ${CFLAGS} mkey.c `xml2-config --cflags` `xml2-config --libs` -lccnsync -lccn -lcrypto -o mkey

clean:
	rm -rf mkey *.dSYM
