#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import base64
import zlib
from pwn import *
from solpow import solve_pow

def decode_message(message):
    data = base64.b64decode(message)
    return zlib.decompress(data[4:])

def encode_message(m):
    zm = zlib.compress(m.encode())
    mlen = len(zm)
    return base64.b64encode(mlen.to_bytes(4, 'little') + zm)

if len(sys.argv) > 1:
    r = remote('up.zoolab.org', 10155)
    solve_pow(r)
else:
    r = process('./guess.dist.py', shell=False)

encoded_msg = r.recvline().strip().decode()
decoded_msg = decode_message(encoded_msg)
print(decoded_msg.decode())  

while True:
    try:
        encoded_msg = r.recvline().strip().decode()
        decoded_msg = decode_message(encoded_msg)
        print(decoded_msg.decode())
        guess = input("")
        r.sendline(encode_message(guess))
        encoded_msg = r.recvline().strip().decode()
        decoded_msg = decode_message(encoded_msg)
        print(f"{int(decoded_msg[3])}A{int(decoded_msg[-2])}B")
        encoded_msg = r.recvline().strip().decode()
        decoded_msg = decode_message(encoded_msg)
        print(decoded_msg.decode())

    except:
        print("Can't solve anymore")
        break
