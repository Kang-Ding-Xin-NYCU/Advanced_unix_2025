from pwn import *

elf = ELF('./gotoku')

main_off = elf.symbols['main']
print("main =", hex(main_off))

with open("got_offsets.h", "w") as out:
    out.write("#include <stdint.h>\n")
    out.write("uintptr_t got_offset_list[] = {\n")

    count = 0
    for i in range(1200):
        fn = f"gop_{i+1}"
        if fn in elf.got:
            got_addr = elf.got[fn]
            out.write(f"    0x{got_addr:x}, // {fn}\n")
            count += 1

    out.write("};\n")
    out.write(f"#define MAIN_OFFSET 0x{main_off:x}\n")
    out.write(f"#define MAX_GOP {count}\n")
