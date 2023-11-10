# Default CFLAGS
CFLAGS := -Wall -masm=intel -static -std=c2x
# Libs:
CFLAGS += -luring

# Check if the compiler is gcc or clang
ifneq (,$(filter $(notdir $(CC)),gcc cc))
# CFLAGS += 
else
ifeq ($(notdir $(CC)),clang)
# CFLAGS += 
endif
endif

all: compress

exploit: exp.c
	$(CC) $(CFLAGS) -o initramfs/$@ $^ *.o

userfault: userfault.c
	$(CC) $(CFLAGS) -c $^

compress: userfault exploit
	cd initramfs && \
	find . -print0 \
	| cpio --null -ov --format=newc -R root \
	| gzip -9 > initramfs.cpio.gz && \
	mv ./initramfs.cpio.gz ../

decompress:
	mkdir -p initramfs && \
	cd initramfs && \
	cp ../initramfs.cpio.gz . && \
	gunzip ./initramfs.cpio.gz && \
	cpio -idm < ./initramfs.cpio && \
	rm initramfs.cpio

run: compress
	qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel ./bzImage \
    -append 'console=ttyS0 loglevel=3 oops=panic panic=1 kaslr' \
    -monitor /dev/null \
    -initrd ./initramfs.cpio.gz  \
    -smp cores=2,threads=2 \
    -cpu kvm64,smep,smap \
	-no-reboot \
    -s

clean:
	rm -f initramfs/exploit