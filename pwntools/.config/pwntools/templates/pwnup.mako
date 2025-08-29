<%page args="binary, host=None, port=None, user=None, password=None, libc=None, remote_path=None, quiet=False"/>\
<%
import os
import sys

from pwnlib.context import context as ctx
from pwnlib.elf.elf import ELF
from elftools.common.exceptions import ELFError

if not binary:
    binary = './path/to/binary'

exe = os.path.basename(binary)

binary_repr = repr(binary)
%>\
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = "tmux neww -a".split()

exe = context.binary = ELF(args.EXE or ${binary_repr})
libc = exe.libc
assert libc is not None


def start(argv=[], *a, **kw):
    if args.REMOTE:
        return remote(args.HOST, args.PORT)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


gdbscript = """
continue
""".format(
    **locals()
)

io = start()
io.interactive()
