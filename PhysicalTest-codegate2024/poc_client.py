import hashlib
import base64
from pwn import *

REMOTE_IP = "127.0.0.1"
REMOTE_PORT = 1337

EXPLOIT_URL = b"??"

io = remote(REMOTE_IP, REMOTE_PORT)

def solvepow(x, target):
    x = bytes.fromhex(x)
    target = bytes.fromhex(target)
    for i in range(256**3):
        if hashlib.md5(x + i.to_bytes(3, "big")).digest() == target:
            return x.hex()+hex(i)[2:]

def main():
    line = io.recvuntil(b"\n")
    x = line.split(b"= ")[1][:26].decode("utf-8")
    target = line.split(b"= ")[2][:32].decode("utf-8")
    io.recvuntil(b": ")
    io.sendline(bytes(solvepow(x, target), "utf-8"))
    io.recvuntil(b"link\n")
    io.sendline(b"1")
    io.recvuntil(b": ")
    f = open("/home/ctf/ex", "rb")
    data = base64.b64encode(f.read())
    f.close()
    io.sendline(data)
    # io.sendline(EXPLOIT_URL)
    io.interactive()
    return

if __name__ == '__main__':
    main()
