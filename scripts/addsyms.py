#!/usr/bin/python

import subprocess
import re

def objdump(*args):
    output = subprocess.run(["objdump", *args], stdout=subprocess.PIPE)
    return output.stdout

def objcopy(*args):
    output = subprocess.run(["objcopy", *args], stdout=subprocess.PIPE)
    return output.stdout

def add_global_symbols(dst, src, symbols):
    args = []
    for (function, section, offset, type) in symbols:
        assert (type in ["function", "object"])
        args.append("--add-symbol")
        args.append(f"{function}={section}:{offset},{type},global")
    objcopy(*args, src, dst)

def get_section_addrs(name):
    output = objdump('-h', name)
    pattern = re.compile(r"^\s*\d+\s+([a-zA-Z.]+)\s+([a-fA-F0-9]+)\s+([a-fA-F0-9]+).+$")

    section_addrs = []
    for i in output.split(b'\n'):
        i = i.decode()
        section = pattern.findall(i)
        if section == []:
            continue
        assert(len(section) == 1)
        (name, size, vma) = section[0]
        section_addrs.append((name, int(size, 16), int(vma, 16)))
    return section_addrs

def get_section_offset(addr, section_addrs):
    for (name, size, vma) in section_addrs:
        if vma <= addr and addr < vma + size:
            return (name, addr - vma)

    raise ValueError(f"invalid addr: {addr:x}")

def main(dst, src, hints):
    section_addrs = get_section_addrs(src)
    
    symbols = []
    for (function, addr, type) in hints:
        (section, offset) = get_section_offset(addr, section_addrs)
        symbols.append((function, section, offset, type))
    
    add_global_symbols(dst, src, symbols)


################################################################################################

# rewrite here
SRC = "src"
DST = "dst"
HINTS = [
    ("main", 0x114d, "function"),
    ("var", 0x4010, "object")
]

main(DST, SRC, HINTS)

