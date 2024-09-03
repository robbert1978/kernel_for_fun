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
	$(CC) $(CFLAGS) -o rootfs/$@ $^

compress: exploit
	cd rootfs && \
	find . -print0 \
	| cpio --null -ov --format=newc -R root > rootfs.cpio && \
	mv ./rootfs.cpio ../ && \
	cd .. && \
	gzip -f rootfs.cpio

decompress:
	mkdir -p rootfs && \
	cd rootfs && \
	cp ../rootfs.cpio . && \
	cpio -idm < ./rootfs.cpio && \
	rm rootfs.cpio

clean:
	rm -f rootfs/exploit
