obj-m := dexter.o
#KBUILD_DIR := /lib/modules/$(KVERSION)/build
KBUILD_DIR := /home/ptr/armoury/buildroot/output/build/linux-5.17.1

all:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) modules

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) clean
