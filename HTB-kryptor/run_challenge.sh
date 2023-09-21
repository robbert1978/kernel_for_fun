#!/bin/sh

qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel "./bzImage" \
    -append "console=ttyS0 quiet loglevel=3 oops=panic panic=-1 pti=on kaslr" \
    -monitor /dev/null \
    -initrd "./initramfs.cpio.gz" \
    -cpu qemu64,+smep,+smap,+rdrand \
    -smp cores=2 \
    -no-reboot \
    -s

