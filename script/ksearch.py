#!/usr/bin/env python

from pwn import *
from sys import argv

if len(argv) < 2:
    exit(1)

vmlinux = argv[1]
elf = ELF(vmlinux)

def search(key):
    print("===============================")
    print(f"{key}")
    for i in elf.search(key):
        offset = i - elf.address
        print(f"   address = 0x{i:x}, offset = 0x{offset:x}")

search(b"/sbin/modprobe\x00")
search(b"core\x00")
search(b"/sbin/poweroff\x00")
