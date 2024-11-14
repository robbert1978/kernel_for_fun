#!/bin/sh
exec qemu-system-x86_64 \
    -kernel bzImage \
    -cpu qemu64,+smep,+smap,+rdrand \
    -m 512M \
    -smp 2 \
    -initrd initramfs.cpio.gz \
    -append "console=ttyS0 quiet loglevel=3 oops=panic panic_on_warn=1 panic=-1 pti=on page_alloc.shuffle=1 kaslr" \
	-drive file=flag,if=virtio,format=raw,readonly=on \
    -monitor /dev/null \
    -nographic \
    -no-reboot
