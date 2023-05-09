obj-m += kstack.o
all:
		make -C ../linux-4.19.98/ M=$(PWD) modules
		EXTRA_CFLAGS="-g DDEBUG"
clean:
		make -C ../linux-4.19.98/ M=$(PWD) clean
