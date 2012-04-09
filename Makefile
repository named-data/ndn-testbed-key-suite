.PHONY: all clean

all: mkey sync pem

mkey: mkey.c
	gcc mkey.c `xml2-config --cflags` `xml2-config --libs` -lccn -lcrypto -o mkey

sync: sync.c
	gcc sync.c -lccn -lcrypto -o sync

pem: pem.c
	gcc pem.c -lcrypto -o pem

clean:
	rm -rf mkey sync pem
