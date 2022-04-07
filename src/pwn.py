#!/usr/bin/env python3

PROGRAM = ''
from pwn import *

context.binary    = PROGRAM
# context.arch      = 'amd64'
context.terminal  = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

con = process([PROGRAM], env={})
# con = remote('', 80)

elf = ELF(PROGRAM)

# EXAMPLES
# elf.bss()
# elf.plt.fun
# elf.got.fun
# elf.address = 0xdeadbeef
# flat(0xdeadbeef, 0xdeadbeef, ...)
# gdb.attach(con)
# constants.SYS_execv
# con.sendlineafter('>', '0')

con.interactive()
