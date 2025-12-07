# Default CFLAGS
CFLAGS := -Wall -masm=intel -static -std=c2x

# Check if the compiler is gcc or clang
ifneq (,$(filter $(notdir $(CC)),gcc cc))
# CFLAGS += 
else
ifeq ($(notdir $(CC)),clang)
# CFLAGS += 
endif
endif

all: exploit

exploit: exp.c
	$(CC) $(CFLAGS) -o initramfs/$@ $^

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
