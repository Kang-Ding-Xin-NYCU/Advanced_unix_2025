#!/usr/bin/env python3
from pwn import *

def get_ip():
    context.log_level = 'error'
    conn = remote("ipinfo.io", 80)

    request = b"GET /ip HTTP/1.1\r\nHost: ipinfo.io\r\nUser-Agent: curl/7.88.1\r\nAccept: */*\r\n\r\n"

    conn.send(request)

    response = conn.recvall(timeout=0.5).decode()

    conn.close()

    ip_address = response.split("\r\n\r\n", 1)[-1].strip()

    print(ip_address, end = "")

if __name__ == "__main__":
    get_ip()

