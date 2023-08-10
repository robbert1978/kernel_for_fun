#!/bin/sh
sudo mount rootfs.img rootfs
sudo gcc -static -no-pie exp.c -o rootfs/exp
sudo umount rootfs