qemu-system-x86_64 \
-m 2G \
-kernel ./bzImage \
-drive file=./rootfs.img,format=raw,index=0,media=disk \
-append "root=/dev/sda rw console=ttyS0 oops=panic panic=1 pti=on kaslr init=/init" \
-netdev user,id=net0,hostfwd=tcp::10022-:22,hostfwd=tcp::9000-:9000 \
-device e1000,netdev=net0,id=nic0 \
-nographic \
-cpu qemu64 --enable-kvm --no-reboot \
