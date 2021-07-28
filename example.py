#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ template_builder.py

from pwn import *
# Many built-in settings can be controlled on the 
# command-line and show up in "args".
# DEBUG, HOST, PORT, EXE, CRASH 

crash = args.CRASH or 'output.json'
exe = ELF(args.EXE or '../path/to/exe')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)
# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

# EXTARCTED DATA FROM CRASH

# sanitizer = AddressSanitizer
# error type = heap-buffer-overflow
# error address = 0x604000003738
# registers state
    # pc = 0x000000554a72
    # bp = 0x7ffe9f593480
    # sp = 0x7ffe9f593478

# type = sanitizer header
# operation = READ
# size = 4
# address = 0x604000003738
# thread = T0

# address = 0x554a71
# function = heap_overflow(unsigned char const*, unsigned long)
# file
    # path = /mnt/hgfs/f/DSEC/fuzzer/heap_overflow/hof.cpp
    # line = 14
    # position = 19

# address = 0x554b34
# function = LLVMFuzzerTestOneInput
# file
    # path = /mnt/hgfs/f/DSEC/fuzzer/heap_overflow/hof.cpp
    # line = 23
    # position = 5

# address = 0x45b691
# function = fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)

# address = 0x45add5
# function = fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool*)

# address = 0x45c800
# function = fuzzer::Fuzzer::MutateAndTestOne()

# address = 0x45d275
# function = fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, fuzzer::fuzzer_allocator<fuzzer::SizedFile> >&)

# address = 0x44cc85
# function = fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long))

# address = 0x4748d2
# function = main

# address = 0x7f4e97929d09
# function = __libc_start_main
# file
    # path = csu/../csu/libc-start.c
    # line = 308
    # position = 16

# address = 0x4214a9
# function = _start


# type = region location
# error description = 0x604000003738 is located 0 bytes to the right of 40-byte region [0x604000003710,0x604000003738)


# type = region location
# error description = 0x604000003738 is located 0 bytes to the right of 40-byte region [0x604000003710,0x604000003738)

# event = allocated
# thread = T0

# address = 0x5520dd
# function = operator new[](unsigned long)

# address = 0x554924
# function = heap_overflow(unsigned char const*, unsigned long)
# file
    # path = /mnt/hgfs/f/DSEC/fuzzer/heap_overflow/hof.cpp
    # line = 8
    # position = 18

# address = 0x554b34
# function = LLVMFuzzerTestOneInput
# file
    # path = /mnt/hgfs/f/DSEC/fuzzer/heap_overflow/hof.cpp
    # line = 23
    # position = 5

# address = 0x45b691
# function = fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)

# address = 0x45add5
# function = fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool*)

# address = 0x45c800
# function = fuzzer::Fuzzer::MutateAndTestOne()

# address = 0x45d275
# function = fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, fuzzer::fuzzer_allocator<fuzzer::SizedFile> >&)

# address = 0x44cc85
# function = fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long))

# address = 0x4748d2
# function = main

# address = 0x7f4e97929d09
# function = __libc_start_main
# file
    # path = csu/../csu/libc-start.c
    # line = 308
    # position = 16



# type = shadow map
# 0x0c087fff8690 = fa fa fd fd fd fd fd fa fa fa fd fd fd fd fd fa 
# 0x0c087fff86a0 = fa fa fd fd fd fd fd fa fa fa fd fd fd fd fd fa 
# 0x0c087fff86b0 = fa fa fd fd fd fd fd fa fa fa fd fd fd fd fd fa 
# 0x0c087fff86c0 = fa fa fd fd fd fd fd fa fa fa fd fd fd fd fd fa 
# 0x0c087fff86d0 = fa fa fd fd fd fd fd fa fa fa fd fd fd fd fd fa 
# 0x0c087fff86e0 = fa fa 00 00 00 00 00 [fa] fa fa fa fa fa fa fa fa 
# 0x0c087fff86f0 = fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa 
# 0x0c087fff8700 = fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa 
# 0x0c087fff8710 = fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa 
# 0x0c087fff8720 = fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa 
# 0x0c087fff8730 = fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa 

# type = crash input
# value = \n\n\n\n\n\x00'

io = start()

# payload = b''
# payload += b'0xdeadbeef'
# payload.ljust(48, b'_')
# io.send(payload)
# flag = io.recvline()
# log.success(flag)

io.interactive()
