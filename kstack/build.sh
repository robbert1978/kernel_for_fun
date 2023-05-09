#!/bin/sh
cd linux-*
rm -rf .config

make distclean
make defconfig

echo "CONFIG_NET_9P=y" >> ./.config
echo "CONFIG_NET_9P_DEBUG=n" >> ./.config
echo "CONFIG_9P_FS=y" >> ./.config
echo "CONFIG_9P_FS_POSIX_ACL=y" >> ./.config
echo "CONFIG_9P_FS_SECURITY=y" >> ./.config
echo "CONFIG_NET_9P_VIRTIO=y" >> ./.config
echo "CONFIG_VIRTIO_PCI=y" >> ./.config
echo "CONFIG_VIRTIO_BLK=y" >> ./.config
echo "CONFIG_VIRTIO_BLK_SCSI=y" >> ./.config
echo "CONFIG_VIRTIO_NET=y" >> ./.config
echo "CONFIG_VIRTIO_CONSOLE=y" >> ./.config
echo "CONFIG_HW_RANDOM_VIRTIO=y" >> ./.config
echo "CONFIG_DRM_VIRTIO_GPU=y" >> ./.config
echo "CONFIG_VIRTIO_PCI_LEGACY=y" >> ./.config
echo "CONFIG_VIRTIO_BALLOON=y" >> ./.config
echo "CONFIG_VIRTIO_INPUT=y" >> ./.config
echo "CONFIG_CRYPTO_DEV_VIRTIO=y" >> ./.config
echo "CONFIG_BALLOON_COMPACTION=y" >> ./.config
echo "CONFIG_PCI=y" >> ./.config
echo "CONFIG_PCI_HOST_GENERIC=y" >> ./.config
echo "CONFIG_GDB_SCRIPTS=y" >> ./.config
echo "CONFIG_DEBUG_INFO=y" >> ./.config
echo "CONFIG_DEBUG_INFO_REDUCED=n" >> ./.config
echo "CONFIG_DEBUG_INFO_SPLIT=n" >> ./.config
echo "CONFIG_DEBUG_FS=y" >> ./.config
echo "CONFIG_DEBUG_INFO_DWARF4=y" >> ./.config
echo "CONFIG_DEBUG_INFO_BTF=y" >> ./.config
echo "CONFIG_FRAME_POINTER=y" >> ./.config


sed -i 'N;s/WARN("missing symbol table");\n\t\treturn -1;/\n\t\treturn 0;\n\t\t\/\/ A missing symbol table is actually possible if its an empty .o file.  This can happen for thunk_64.o./g' ./tools/objtool/elf.c

sed -i 's/unsigned long __force_order/\/\/ unsigned long __force_order/g' ./arch/x86/boot/compressed/pgtable_64.c

make -j16 bzImage

cp arch/x86/boot/bzImage ../

cd ../