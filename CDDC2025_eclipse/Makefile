# Default CFLAGS
CFLAGS := -Wall -masm=intel -static -std=c2x
LDFLAGS := $(shell pkg-config --libs fuse) -luring
CC := gcc

all: exploit

exploit: exp.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

compress: exploit
	sudo mount rootfs.img rootfs && \
	sudo cp exploit rootfs && \
	sudo umount rootfs
