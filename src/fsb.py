#!/usr/bin/env python3

PROGRAM = ''

from pwn import *

context.binary    = PROGRAM
# context.arch      = 'amd64'
context.terminal  = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

con = process([PROGRAM], env={})
# con = remote('', 80)
# con = gdb.debug([PROGRAM], env={}, gdbscript='continue')

elf = ELF(PROGRAM)

def exec_fmt(payload):
    con = process([PROGRAM], env={})
    return con.recvline()

autofmt = FmtStr(exec_fmt)
# payload = fmtstr_payload(autofmt.offset, {0xabc: 0xdef})

con.interactive()
