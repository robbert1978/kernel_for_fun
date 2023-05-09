#!/bin/sh
rm ./initramfs.cpio
chmod 777 -R ./initramfs
cd ./initramfs
find ./ -print0 | cpio --owner root --null -o --format=newc > ../initramfs.cpio
cd ../
