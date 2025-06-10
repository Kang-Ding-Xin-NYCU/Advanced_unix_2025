#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sched.h>
#include <dlfcn.h>

extern void syscall_addr(void);
extern long enter_syscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
extern void asm_syscall_hook(void);

void ____asm_impl(void)
{
    /*
     * enter_syscall 觸發一個系統調用
     */
    asm volatile (
    ".globl enter_syscall \n\t"
    "enter_syscall: \n\t"
    "movq %rdi, %rax \n\t"
    "movq %rsi, %rdi \n\t"
    "movq %rdx, %rsi \n\t"
    "movq %rcx, %rdx \n\t"
    "movq %r8, %r10 \n\t"
    "movq %r9, %r8 \n\t"
    "movq 8(%rsp),%r9 \n\t"
    ".globl syscall_addr \n\t"
    "syscall_addr: \n\t"
    "syscall \n\t"
    "ret \n\t"
    );

    /*
     * asm_syscall_hook 是蹦床代碼的著陸點
     */
    asm volatile (
    ".globl asm_syscall_hook \n\t"
    "asm_syscall_hook: \n\t"

    "cmpq $15, %rax \n\t" // rt_sigreturn
    "je do_rt_sigreturn \n\t"
    "pushq %rbp \n\t"
    "movq %rsp, %rbp \n\t"

    /*
     * 對於 xmm 寄存器操作，堆疊需要16位元組對齊
     */
    "andq $-16, %rsp \n\t" // 16 位元組堆疊對齊

    /* 保存寄存器 */
    "pushq %r11 \n\t"
    "pushq %r9 \n\t"
    "pushq %r8 \n\t"
    "pushq %rdi \n\t"
    "pushq %rsi \n\t"
    "pushq %rdx \n\t"
    "pushq %rcx \n\t"

    /* syscall_hook 的參數 */
    "pushq 136(%rbp) \n\t"    // 返回地址
    "pushq %rax \n\t"
    "pushq %r10 \n\t"

    /* 堆疊已16位元組對齊 */
    "callq syscall_hook@plt \n\t"

    "popq %r10 \n\t"
    "addq $16, %rsp \n\t"     // 丟棄 arg7 和 arg8

    "popq %rcx \n\t"
    "popq %rdx \n\t"
    "popq %rsi \n\t"
    "popq %rdi \n\t"
    "popq %r8 \n\t"
    "popq %r9 \n\t"
    "popq %r11 \n\t"

    "leaveq \n\t"

    "addq $128, %rsp \n\t"

    "retq \n\t"

    "do_rt_sigreturn:"
    "addq $136, %rsp \n\t"
    "jmp syscall_addr \n\t"
    );
}

static long (*hook_fn)(int64_t a1, int64_t a2, int64_t a3,
                int64_t a4, int64_t a5, int64_t a6,
                int64_t a7) = enter_syscall;

long syscall_hook(int64_t rdi, int64_t rsi,
           int64_t rdx, int64_t __rcx __attribute__((unused)),
           int64_t r8, int64_t r9,
           int64_t r10_on_stack /* 4th arg for syscall */,
           int64_t rax_on_stack,
           int64_t retptr)
{
    // 系統調用號為 1 (write) 且文件描述符為 1 (stdout)
    if (rax_on_stack == 1 && rdi == 1) {
        // 轉換 leetspeak 到普通文字
        char *buffer = (char *)rsi;
        int count = rdx;
        
        for (int i = 0; i < count; i++) {
            switch (buffer[i]) {
                case '0': buffer[i] = 'o'; break;
                case '1': buffer[i] = 'i'; break;
                case '2': buffer[i] = 'z'; break;
                case '3': buffer[i] = 'e'; break;
                case '4': buffer[i] = 'a'; break;
                case '5': buffer[i] = 's'; break;
                case '6': buffer[i] = 'g'; break;
                case '7': buffer[i] = 't'; break;
            }
        }
    }

    if (rax_on_stack == 435 /* __NR_clone3 */) {
        uint64_t *ca = (uint64_t *) rdi; /* struct clone_args */
        if (ca[0] /* flags */ & CLONE_VM) {
            ca[6] /* stack_size */ -= sizeof(uint64_t);
            *((uint64_t *) (ca[5] /* stack */ + ca[6] /* stack_size */)) = retptr;
        }
    }

    if (rax_on_stack == __NR_clone) {
        if (rdi & CLONE_VM) { // pthread creation
            /* push return address to the stack */
            rsi -= sizeof(uint64_t);
            *((uint64_t *) rsi) = retptr;
        }
    }

    return hook_fn(rax_on_stack, rdi, rsi, rdx, r10_on_stack, r8, r9);
}

// 設置 trampoline
static void setup_trampoline(void)
{
    void *mem;

    /* 在虛擬地址 0 分配記憶體 */
    mem = mmap(0 /* virtual address 0 */, 0x1000,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
            -1, 0);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "map failed\n");
        fprintf(stderr, "NOTE: /proc/sys/vm/mmap_min_addr should be set 0\n");
        exit(1);
    }

    {
        int i;
        for (i = 0; i < 512; i++)
            ((uint8_t *) mem)[i] = 0x90;
    }

    /* 
     * 放置跳轉到 asm_syscall_hook 的代碼
     */

    /* 保留紅區 */
    // 48 81 ec 80 00 00 00    sub    $0x80,%rsp
    ((uint8_t *) mem)[512 + 0x00] = 0x48;
    ((uint8_t *) mem)[512 + 0x01] = 0x81;
    ((uint8_t *) mem)[512 + 0x02] = 0xec;
    ((uint8_t *) mem)[512 + 0x03] = 0x80;
    ((uint8_t *) mem)[512 + 0x04] = 0x00;
    ((uint8_t *) mem)[512 + 0x05] = 0x00;
    ((uint8_t *) mem)[512 + 0x06] = 0x00;

    // 49 bb [64-bit addr (8-byte)]    movabs [64-bit addr (8-byte)],%r11
    ((uint8_t *) mem)[512 + 0x07] = 0x49;
    ((uint8_t *) mem)[512 + 0x08] = 0xbb;
    ((uint8_t *) mem)[512 + 0x09] = ((uint64_t) asm_syscall_hook >> (8 * 0)) & 0xff;
    ((uint8_t *) mem)[512 + 0x0a] = ((uint64_t) asm_syscall_hook >> (8 * 1)) & 0xff;
    ((uint8_t *) mem)[512 + 0x0b] = ((uint64_t) asm_syscall_hook >> (8 * 2)) & 0xff;
    ((uint8_t *) mem)[512 + 0x0c] = ((uint64_t) asm_syscall_hook >> (8 * 3)) & 0xff;
    ((uint8_t *) mem)[512 + 0x0d] = ((uint64_t) asm_syscall_hook >> (8 * 4)) & 0xff;
    ((uint8_t *) mem)[512 + 0x0e] = ((uint64_t) asm_syscall_hook >> (8 * 5)) & 0xff;
    ((uint8_t *) mem)[512 + 0x0f] = ((uint64_t) asm_syscall_hook >> (8 * 6)) & 0xff;
    ((uint8_t *) mem)[512 + 0x10] = ((uint64_t) asm_syscall_hook >> (8 * 7)) & 0xff;

    // 41 ff e3                jmp    *%r11
    ((uint8_t *) mem)[512 + 0x11] = 0x41;
    ((uint8_t *) mem)[512 + 0x12] = 0xff;
    ((uint8_t *) mem)[512 + 0x13] = 0xe3;

    /*
     * 設置為僅執行權限
     */
    assert(!mprotect(0, 0x1000, PROT_EXEC));
}

// 直接掃描並替換 syscall 指令
static void rewrite_code(void *addr, size_t size)
{
    if (addr == NULL || size < 2) return;
    
    // 檢查是否為 trigger_syscall
    void *trigger_syscall_ptr = (void *)syscall_addr;
    if (addr <= trigger_syscall_ptr && (char*)addr + size > (char*)trigger_syscall_ptr) {
        return;  // 不重寫我們自己的 syscall
    }
    
    uint8_t *code = (uint8_t *)addr;
    
    // 修改記憶體權限
    if (mprotect(addr, size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return;  // 跳過無法修改的區域
    }
    
    // 掃描並替換 syscall 指令
    for (size_t i = 0; i < size - 1; i++) {
        if (code[i] == 0x0F && code[i + 1] == 0x05) {
            code[i] = 0xFF;  // call
            code[i + 1] = 0xD0;  // *%rax
        }
    }
    
    // 恢復記憶體權限
    mprotect(addr, size, PROT_READ | PROT_EXEC);
}

// 掃描並重寫所有可執行區域
static void rewrite_all_code(void)
{
    FILE *fp;
    /* 從 /proc/self/maps 獲取記憶體映射 */
    fp = fopen("/proc/self/maps", "r");
    if (!fp) return;
    
    char line[4096];
    while (fgets(line, sizeof(line), fp) != NULL) {
        // 排除堆疊和特殊區域
        if (strstr(line, "[stack]") || strstr(line, "[vsyscall]") || strstr(line, "[vdso]"))
            continue;
        
        // 解析記憶體映射行
        unsigned long start, end;
        char perms[5];
        
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
            continue;
        
        // 只處理可執行區域
        if (strchr(perms, 'x')) {
            // 跳過地址 0 處的 trampoline
            if (start == 0)
                continue;
                
            size_t size = end - start;
            void *addr = (void *)start;
            
            rewrite_code(addr, size);
        }
    }
    
    fclose(fp);
}

__attribute__((constructor)) static void init(void)
{
    setup_trampoline();
    rewrite_all_code();
}