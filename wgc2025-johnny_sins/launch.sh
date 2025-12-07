#!/bin/sh
qemu-system-x86_64 \
    -kernel bzImage \
    -cpu kvm64,+smap,+smep \
    -smp cores=2 \
    -m 1G \
    -initrd $PWD/initramfs.cpio.gz \
    -drive file=$PWD/flag,if=virtio,format=raw,readonly=on \
    -nic user,model=e1000 \
    -nographic \
    -monitor none \
    -append "console=ttyS0 log_level=3 pti=on"
