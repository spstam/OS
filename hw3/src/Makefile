all:
	gcc -g -Wall bbfs.c log.c \
	$(shell pkg-config fuse --cflags --libs) \
	$(shell pkg-config libssl libcrypto --cflags --libs) -o bbfs

clean:
	rm -rf ./bbfs