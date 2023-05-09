#!/bin/sh

gcc vjp.c -o initramfs/exploit -static -no-pie -pthread
gcc demo.c -o initramfs/demo -static -no-pie