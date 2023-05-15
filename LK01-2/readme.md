# Heap overflow
## Heap spray go go brr
## Overwrite  modprobe_path

Khi có một file không thuộc dạng Ascii( Shell script) hay ELF thì hàm `call_modprobe` sẽ được gọi ra.

Mình build lại kernel để dễ debug, tạo một file với magic bytes "lạ" rồi thực thi nó, ta thấy hàm `call_modprobe`  đã được gọi ra.
![image](https://github.com/robbert1978/kernel_for_fun/assets/31349426/ae20209e-1355-4b65-a306-1bdc1fe39c72)

Backtrace đễ xem đã đi qua những hàm nào:
![image](https://github.com/robbert1978/kernel_for_fun/assets/31349426/66fd6671-687e-4674-b7a8-3f9aa1f9877c)

1.  __x64_sys_execve
2.  do_execveat_common
3.  bprm_execve
4.  __request_module
5.  call_modprobe

Xem code hàm `call_modprobe`:
```c
pwndbg> list 86
66              kfree(info->argv);
67      }
68
69      static int call_modprobe(char *module_name, int wait)
70      {
71              struct subprocess_info *info;
72              static char *envp[] = {
73                      "HOME=/",
74                      "TERM=linux",
75                      "PATH=/sbin:/usr/sbin:/bin:/usr/bin",
76                      NULL
77              };
78
79              char **argv = kmalloc(sizeof(char *[5]), GFP_KERNEL);
80              if (!argv)
81                      goto out;
82
83              module_name = kstrdup(module_name, GFP_KERNEL);
84              if (!module_name)
85                      goto free_argv;
86
87              argv[0] = modprobe_path;
88              argv[1] = "-q";
89              argv[2] = "--";
90              argv[3] = module_name;  /* check free_modprobe_argv() */
91              argv[4] = NULL;
92
93              info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
94                                               NULL, free_modprobe_argv, NULL);
95              if (!info)
96                      goto free_module_name;
97
98              return call_usermodehelper_exec(info, wait | UMH_KILLABLE);
99
100     free_module_name:
101             kfree(module_name);
102     free_argv:
103             kfree(argv);
104     out:
105             return -ENOMEM;
106     }
```

Ta break ở line 93 để xem modprobe_path: 
![image](https://github.com/robbert1978/kernel_for_fun/assets/31349426/f3e0a04a-84f1-44ef-9a0e-83ce95dc00b2)

Ta thấy `modprobe_path` lại nằm ở trong vùng RW.
Từ đó khi ghi đè `modprobe_path` thành đường dẫn file thực thi quả mình ( có thể là shell script hoặc ELF) thì file đó sẽ được thi thực thi với quyền root -> leo thang.

Cá nhân mình thấy cách này stable hơn Stack piviot, vì các gadgets như `mov ... [rdx],rsi` xác suất thì thấy thường sẽ rất nhiều.

