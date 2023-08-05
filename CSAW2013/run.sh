#! /bin/sh

qemu-system-x86_64 \
    -m 128M \
    -kernel bzImage \
    -cpu host,+smap,+smep \
    -initrd initramfs.cpio.gz \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr" \
    -smp 2 \
    -monitor /dev/null \
    -enable-kvm \
    -no-reboot \
    -nographic \
    -s
