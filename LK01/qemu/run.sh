#!/bin/sh
qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=1 kpti kaslr" \
    -no-reboot \
    -cpu qemu64,+smep,+smap \
    -smp 1 \
    -monitor /dev/null \
    -initrd ../rootfs.cpio.gz \
    -net nic,model=virtio \
    -net user \
    -s
