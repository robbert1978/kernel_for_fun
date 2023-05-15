from pwn import ELF,log

kernel = ELF("./vmlinux")

_ = hex(next(kernel.search(b"/sbin/modprobe")))
log.info(f"{_}")
