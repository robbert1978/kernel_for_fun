# Default CFLAGS
CFLAGS := -Wall -masm=intel -static -no-pie -std=c2x

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
	-L ./bios \
    -kernel ./bzImage \
    -initrd ./initramfs.cpio.gz \
    -cpu kvm64,+smep,+smap \
    -monitor none \
    -m 1024M \
    -append "console=ttyS0 oops=panic panic=1 quiet kaslr" \
    -monitor /dev/null \
    -nographic \
    -no-reboot \
    -net user -net nic -device e1000  \
    -s

clean:
	rm -f initramfs/exploit