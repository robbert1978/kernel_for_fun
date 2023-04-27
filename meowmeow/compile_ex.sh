#!/bin/sh
gcc ./exploit.c -o exploit --static
cp ./exploit ./extracted/
sh ./compress.sh
