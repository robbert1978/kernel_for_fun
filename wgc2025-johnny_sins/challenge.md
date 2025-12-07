# [Johnny Sins](https://ctf.cnsc.com.vn/games/1/challenges?challenge=40)
Author: d4rkn19ht

Des: Ah, the plumber guy, ...

Techniques: Page UAF, ret2pt_reg

Refs:
- https://github.com/Lotuhu/Page-UAF
- https://org.anize.rs/0CTF-2021-finals/pwn/kernote
- https://docs.google.com/presentation/d/e/2PACX-1vR4mpH3aARLMOhJemVGEw1cduXPEo_PvrbZMum8QwOJ6rhZvvezsif4qtgSydVVt8jPT1fztgD5Mj7q/pub?slide=id.g14af4af2bf0_1_97



```
$ ./exploit
[*] tee
[+] proc_single_file_operations @ 0xffffffffaf229760
[+] page_vaddr @ 0xffff95cd42288000
[+] Root!
W1{Th3_s3xy-hOU5e_0wNer_4Nd-thE_LuCKy-p1Um63r_GUY11}

/tmp # id
id
uid=0(root) gid=0 groups=0
```
