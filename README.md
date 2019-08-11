# pwn_category

This is a classification for pwn games that i used to do or recurrent. and all the problem in this repository is typical.


Table of Contents
=================

   * [pwn_category](#pwn_category)
      * [heap](#heap)
         * [global_max_fast](#global_max_fast)
         * [largebin_attack](#largebin_attack)
         * [tcache](#tcache)
         * [sysmalloc](#sysmalloc)
         * [waiting for CATEGORY](#waiting-for-category)
      * [integer_overflow](#integer_overflow)
      * [stack](#stack)
         * [SROP](#srop)
         * [ret2dl_resolve](#ret2dl_resolve)
         * [waiting for CATEGORY](#waiting-for-category-1)
      * [format_string](#format_string)
      * [odd_skill](#odd_skill)
      * [shellcode](#shellcode)
      * [IO_FILE](#io_file)
         * [arbitraty_read_write](#arbitraty_read_write)
         * [vtable_hajack](#vtable_hajack)
         * [vtable_str_jumps](#vtable_str_jumps)
      * [comprehensive](#comprehensive)

Created by [gh-md-toc](https://github.com/ekalinin/github-markdown-toc)

## heap
typical heap problems

### global_max_fast

* 0ctf2016-zerostorage

    game: 0ctf 2016

    description: an implicit uaf with unsorted bin attack

    writeup link: []()

* bctf2018-baby_arena

    game: bctf 2018

    description: a arbitrary address overwrite with a uncontrollable value

    writeup link: [https://ray-cp.github.io/archivers/heap_global_max_fast_exploit#baby_arena](https://ray-cp.github.io/archivers/heap_global_max_fast_exploit#baby_arena)

* starctf2019-heap_master

    game: starctf 2019

    description: uaf, io file, unsorted bin attack with 4bit brute

    writeup link: [https://ray-cp.github.io/archivers/heap_global_max_fast_exploit#heap_master](https://ray-cp.github.io/archivers/heap_global_max_fast_exploit#heap_master)

### largebin_attack

* lctf2017-2ez4u

    game: lctf 2017

    description: a typical largebin attack problem with fake bk_nextsize.

    writeup link: [Large bin attack--LCTF2017-2ez4u--writeup](https://ray-cp.github.io/archivers/Large%20bin%20attack--LCTF2017-2ez4u--writeup)

* 0ctf2018-heapstorm2

    game: 0ctf 2018

    description: a typical largebin attack problem(house of storm).

    writeup link: []()

* rctf2019-babyheap

    game: rctf 2019

    description: a typical largebin attack problem(house of storm).

    writeup link: []()

### tcache 

* hitb2018-gundam

  game: hitb 2018

  description: a easy uaf with tcache.

  writeup link: none

* codegate2019-god-the-reum 

  game: codegate 2019

  description: a easy uaf in `withdraw` function with tcache.

  writeup link: none

* lctf2018-easy_heap 

  game: lctf 2018

  description:  build fake unlink with unsorted_bin chain then uaf.

  writeup link: none

* hitcon2018-children_tcache 

  game: hitcon2018

  description:  unlink to form overlap chunk by off-by-null vuln.

  writeup link: none

* hitcon2018-baby_tcache 

  game: hitcon2018

  description:  unlink to form overlap chunk by off-by-null vuln, and brute force to overwrite stdout to leak libc address by 4bit brute force.

  writeup link: none

* bctf2018-three

  game: bctf 2018

  description:  uaf to brute force to overwrite stdout to leak libc address by 4bit brute force, only three chunks allowed.

  writeup link: none

* bctf2018-houseofAtum 

  game: bctf 2018

  description:  tcache and fastbin chain to form the 0x10 byte backwards.

  writeup link: none

* starctf2019-girlfriend 

  game: starctf 2019

  description:  bypass double free check for tcache in glibc 2.29.

  writeup link: none



### sysmalloc
some exp with sysmalloc function

* rctf2019-many_note

    game: rctf 2019

    description: thread arena, expand top chunk, tough to trigger free

    writeup link: [https://ray-cp.github.io/archivers/RCTF_2019_PWN_WRITEUP#many_note](https://ray-cp.github.io/archivers/RCTF_2019_PWN_WRITEUP#many_note)

### waiting for CATEGORY

* AddressSanitizer-uaf-0ctf2019-aegis

    game: 0ctf 2019

    description: AddressSanitizer is a memory protection that developed by google. it's a uaf problem.

    writeup link: [https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#aegis](https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#aegis)

* overlap_chunk-malloc_consolidate-0ctf2019-babyheap
    game: 0ctf 2019

    description: `off-by-null` to form overlap_chunk, it also pwned by triggering `malloc_consolidate` when top chunk is too small.

    writeup link: [https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#babyheap](https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#babyheap)
* race_condition-uaf-0ctf2019-zerotask

    game: 0ctf 2019

    description: race condition to form `uaf` vuln.

    writeup link: [https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#zerotask](https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#zerotask)
* unlink-heap_brute-强网杯2018-note2

    game: 强网杯 2018

    description: unlink with brute.

    writeup link: none

## integer_overflow

typical integer overflow problems
* source_audit-integer_overflow-0ctf2019-If_on_a_winters_night_a_traveler

    game: 0ctf 2019

    description: give out a perm.diff, need to source audit, it use integer overflow to form `write-to-where` vuln.

    writeup link: [https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#if_on_a_winters_night_a_traveler](https://ray-cp.github.io/archivers/0CTF_2019_PWN_WRITEUP#if_on_a_winters_night_a_traveler)

## stack

typical stack related problems such as stack overflow. 

### SROP

* paper_Framing Signals—A Return to Portable Shellcode.pdf
    paper of srop

* slide_Framing Signals—A Return to Portable Shellcode.pdf
    slide of srop

* 360ichunqiu2017-smallest

    game: 360ichunqiu 2017

    description: srop with stackoverflow.
    
    writeup link: []()

* rctf2019-syscall_interface

    game: rctf 2019

    description: `personality syscall` make heap executable, `brk syscall` leak heap address, `srop` to get shell.
    
    writeup link: []()

### ret2dl_resolve

* 0ctf2018-babystack

    game: 0ctf 2018

    description: ret2dl_resolve in x86 architecture with fake reloc_arg.
    
    writeup link: []()

* hitcon2015-blinkroot

    game: hitcon 2015

    description: ret2dl_resolve in x64 architecture with fake link_map.
    
    writeup link: []()

### waiting for CATEGORY
* partial-stackoverwirte-2018-强网杯-opm

    game: 强网杯 2018

    description: a partial overwrite problem.
    
    writeup link: [https://ray-cp.github.io/archivers/强网杯-pwn-writeup#opm](https://ray-cp.github.io/archivers/强网杯-pwn-writeup#opm)


* partial-stackoverwirte-2018-强网杯-opm

    game: 强网杯 2018

    description: a partial overwrite problem.
    
    writeup link: [https://ray-cp.github.io/archivers/强网杯-pwn-writeup#opm](https://ray-cp.github.io/archivers/强网杯-pwn-writeup#opm)

* pointer-stackoverwrite-starctf2019-quicksort

    game: starctf 2019

    description: overwite heap pointer in stack to leak and write.
    
    writeup link: [https://ray-cp.github.io/archivers/STARCTF_2019_PWN_WRITEUP#quicksort](https://ray-cp.github.io/archivers/STARCTF_2019_PWN_WRITEUP#quicksort)



## format_string

Some typical format vlun.

* 0ctf2017-EasiestPrintf

  game: 0ctf2017

  description:  trigger malloc by printf.

  writeup link: none

* CISCN2017-NotFormat

  game: CISCN2017

  description:  the same as EasiestPrintf, trigger malloc by printf, just on x64 architecture and compiled by static.

  writeup link: none

* 34c3ctf2017-readme_revenge

  game: 34c3 ctf 

  description:  hajack printf table to fortify_fail function to leak flag.

  writeup link: none

* twctf2018-neighbor_c

  game: twctf 2018

  description:  bruteforce to guess stack addr and stdout addt by 4bytes, and change stderr.fileno to 1, which then can leak address. then write one gadget to malloc_hook, at last trigger malloc.

  writeup link: none

* Hack.lu2017_HeapsOfPrint

  game: Hack.lu 2017

  description:  form a loop by format vlun and write by rbp.

  writeup link: none

  

## odd_skill

some odd skill that may suprise me
* rwx-upxpacked-starctf2019-upxofcpp

    game: starctf 2019

    description: a heap double free but with upx pack which form rwx segment.
    
    writeup link: [https://ray-cp.github.io/archivers/STARCTF_2019_PWN_WRITEUP#upxofcpp](https://ray-cp.github.io/archivers/STARCTF_2019_PWN_WRITEUP#upxofcpp)

## shellcode

Examine the ability to write shellcode

* rctf2019-shellcoder

    game: rctf 2019

    description: seven byte shellcode with rdi unclean.
    
    writeup link: [https://ray-cp.github.io/archivers/RCTF_2019_PWN_WRITEUP#shellcoder](https://ray-cp.github.io/archivers/RCTF_2019_PWN_WRITEUP#shellcoder)

## IO_FILE
exploitation with io file structure build.

* play_file_struct.pdf

    description: angelboy's amazing slide with IO FILE.

### arbitraty_read_write
arbitraty read_write with stdin or stdout

* hctf2018-babyprintf_ver2

    game: hctf2018

    description: arbitrary read write with stdout handle.
    
    writeup link: []()

* whctf2017-stackoverflow

    game: whctf2017

    description: a null byte overflow to stdin handle to get shell.
    
    writeup link: []()

### vtable_hajack

hajack IO FILE's vtable to exploit

* 东华杯2016-pwn450_note

    game: 东华杯2016

    description: classic house of orange.
    
    writeup link: []()

### vtable_str_jumps

bypass vtable check with `_IO_str_jumps` vtable.

* ASIS2018-fifty-dollars

    game: ASIS2018

    description: two time fsop.
    
    writeup link: []()

* hctf2017-babyprintf

    game: hctf2017

    description: classic vtable check bypass.
    
    writeup link: []()


## comprehensive

* rctf2019-chat

    game: rctf 2019

    description: chat system with complicated stucture.
    
    writeup link: [https://ray-cp.github.io/archivers/RCTF_2019_PWN_WRITEUP#chat](https://ray-cp.github.io/archivers/RCTF_2019_PWN_WRITEUP#chat)
