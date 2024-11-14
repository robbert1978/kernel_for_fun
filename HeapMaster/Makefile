# Default CFLAGS
CFLAGS := -Wall -masm=intel -static -std=c2x -I/usr/include -I/usr/include/x86_64-linux-gnu
SOURCE := exp.c

# Check if the compiler is gcc or clang
ifneq (,$(filter $(notdir $(CC)),gcc cc))
# CFLAGS += 
else
ifeq ($(notdir $(CC)),clang)
# CFLAGS += 
endif
endif

all: exploit

exploit: $(SOURCE)
	$(CC) $(CFLAGS) -o initramfs/bin/$@ $^

compress: exploit
	cd initramfs && \
	find . -print0 \
	| cpio --null -ov --format=newc -R root \
	| gzip -9 > ../initramfs.cpio.gz

decompress:
	mkdir -p initramfs && \
	cd initramfs && \
	cp ../initramfs.cpio.gz . && \
	gunzip ./initramfs.cpio.gz && \
	cpio -idm < ./initramfs.cpio && \
	rm initramfs.cpio

clean:
	rm -f initramfs/exploit
