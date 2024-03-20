#!/bin/sh

qemu-system-i386 \
    -m 128M \
    -cdrom kernel.iso \
    -boot order=d \
    -no-reboot \
    -nographic \
    -monitor none \
    -drive file="${1:-/dev/null}",format=raw