#!/bin/sh
read -p "Enter the link to your binary: " link

timeout --foreground 300 wget $link -O exploit
chmod 777 ./exploit
sleep 3
./decomp.sh
./comp.sh

timeout --foreground 300 qemu-system-x86_64 \
    -m 256M \
    -cpu kvm64,+smep,+smap \
    -smp 4 \
    -kernel bzImage \
    -initrd initramfs.cpio.gz \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0  kaslr kpti=1  quiet panic=1"



