#Kernpass

A challenge form [Black Bauhinia ctf](https://ctf.b6a.black/)

Pesudocode:
```c
struct Request
{
  uint idx;
  uint size;
  char *data;
};

struct Note
{
  uint size;
  char *data;
};

__int64 __fastcall module_ioctl(__int64 a1, uint cmd, __int64 argc)
{
  char *data; // r14
  Note *v5; // rax
  unsigned __int64 size; // r12
  char *v7; // r13
  __int64 idx; // rbx
  char *data_user; // r14
  Note *v11; // rax
  unsigned __int64 v12; // r12
  char *v13; // r13
  __int64 idx_; // r15
  __int64 size_; // r12
  Note *v16; // rax MAPDST
  char *v18; // rax MAPDST
  char *usr_data; // [rsp-50h] [rbp-50h]
  Request req; // [rsp-48h] [rbp-48h] BYREF
  unsigned __int64 v22; // [rsp-38h] [rbp-38h]

  _fentry__(a1, cmd);
  v22 = __readgsqword(0x28u);
  if ( copy_from_user(&req, argc, 16LL) )
    return -1LL;
  if ( cmd != 0x13370003 )
  {
    if ( cmd > 0x13370003 )
    {
      if ( cmd == 0x13370004 )
      {
        idx = req.idx;
        if ( req.idx <= 0x1F )
        {
          kfree(main_list[req.idx]->data);
          kfree(main_list[idx]);
          main_list[idx] = 0LL;
          return 0LL;
        }
      }
      return -1LL;
    }
    if ( cmd != 0x13370001 )
    {
      if ( cmd == 0x13370002 )
      {
        data = req.data;
        if ( req.idx <= 0x1F )
        {
          v5 = main_list[req.idx];
          if ( v5 )
          {
            size = v5->size;
            v7 = v5->data;
            if ( size <= 0x7FFFFFFF )
            {
              _check_object_size(v5->data, v5->size, 1LL);
              return -(copy_to_user(data, v7, size) != 0);
            }
LABEL_22:
            BUG();
          }
        }
      }
      return -1LL;
    }
    idx_ = req.idx;
    size_ = req.size;
    usr_data = req.data;
    if ( req.idx <= 0x1F && req.size <= 0x200 )
    {
      v16 = (Note *)kmem_cache_alloc_trace(kmalloc_caches[18], 4197568LL, 16LL);
      v16->size = size_;
      v18 = (char *)_kmalloc(size_, 4197568LL);
      v16->data = v18;
      _check_object_size(v18, size_, 0LL);
      if ( copy_from_user(v18, usr_data, size_) )
      {
        kfree(v16);
        return -1LL;
      }
      else
      {
        main_list[idx_] = v16;
        return 0LL;
      }
    }
    return -1LL;
  }
  data_user = req.data;
  if ( req.idx > 0x1F )
    return -1LL;
  v11 = main_list[req.idx];
  if ( !v11 )
    return -1LL;
  v12 = v11->size;
  v13 = v11->data;
  if ( v12 > 0x7FFFFFFF )
    goto LABEL_22;
  _check_object_size(v11->data, v11->size, 0LL);
  return -(copy_from_user(v13, data_user, v12) != 0);
}
```

Use `userfaultfd` to trigger UAF bug.

Use `struct seq_operations` to leak kernel base.

Overwriting `modprobe_path` to get root shell by creating a fake node: `node->size = 0x30` and `note->data = modprobe_path`.

Somehow, there was no error with `_check_object_size(modprobe_path, 0x30, 0LL);`.
