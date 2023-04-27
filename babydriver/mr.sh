#!/bin/bash

## extract filesystem
#sudo rm -rf ./extracted
#mkdir extracted
#cd extracted
#cpio -idv < ../initramfs.cpio
#cd ../

# build and compile exploit
cwd=$(pwd)
rm ./extracted/tmp/exploit
gcc ./exploit.c -o ./exploit --static -g -O0 -masm=intel
cp ./exploit ./extracted/tmp

# compress filesystem
rm ./rootfs.cpio
chmod 777 -R ./extracted
cd ./extracted
find ./ -print0 | cpio --owner root --null -o --format=newc > ../rootfs.cpio
cd ../

