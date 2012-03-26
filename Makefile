.PHONY: all clean

all: mkey sync

mkey: mkey.c
	gcc mkey.c `xml2-config --cflags` `xml2-config --libs` -lcrypto -lccn -o mkey

sync: sync.c
	gcc sync.c -lcrypto -lccn -o sync

clean:
	rm -rf mkey sync
