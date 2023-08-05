obj-m += csaw.o
csaw-objs := main.o

KDIR = ./linux-6.4.8/

default:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	
