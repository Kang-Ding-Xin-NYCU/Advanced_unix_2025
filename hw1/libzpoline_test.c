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
#include <link.h> // for LM_ID_NEWLM

// ========================== 外部符號 ==========================
extern void syscall_addr(void);
extern long enter_syscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
extern void asm_syscall_hook(void);

// ========================== Type 定義 ==========================
typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t,
                                     int64_t, int64_t, int64_t, int64_t);

// ========================== 全域變數 ==========================
static syscall_hook_fn_t hooked_syscall = NULL;
static long (*hook_fn)(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t) = enter_syscall;

// ========================== 低階包裝器 ==========================
static int64_t trigger_syscall(int64_t rdi, int64_t rsi, int64_t rdx,
                               int64_t r10, int64_t r8, int64_t r9,
                               int64_t rax)
{
    return enter_syscall(rax, rdi, rsi, rdx, r10, r8, r9);
}

void ____asm_impl(void)
{
    asm volatile (
    ".globl enter_syscall \n\t"
    "enter_syscall: \n\t"
    "movq %rdi, %rax \n\t"
    "movq %rsi, %rdi \n\t"
    "movq %rdx, %rsi \n\t"
    "movq %rcx, %rdx \n\t"
    "movq %r8, %r10 \n\t"
    "movq %r9, %r8 \n\t"
    "movq 8(%rsp), %r9 \n\t"
    ".globl syscall_addr \n\t"
    "syscall_addr: \n\t"
    "syscall \n\t"
    "ret \n\t"
    );

    asm volatile (
    ".globl asm_syscall_hook \n\t"
    "asm_syscall_hook: \n\t"
    "cmpq $15, %rax \n\t" // rt_sigreturn
    "je do_rt_sigreturn \n\t"
    "pushq %rbp \n\t"
    "movq %rsp, %rbp \n\t"
    "andq $-16, %rsp \n\t"

    "pushq %r11 \n\t"
    "pushq %r9 \n\t"
    "pushq %r8 \n\t"
    "pushq %rdi \n\t"
    "pushq %rsi \n\t"
    "pushq %rdx \n\t"
    "pushq %rcx \n\t"

    "pushq 136(%rbp) \n\t"
    "pushq %rax \n\t"
    "pushq %r10 \n\t"

    "callq syscall_hook@plt \n\t"

    "popq %r10 \n\t"
    "addq $16, %rsp \n\t"

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

    "do_rt_sigreturn:\n\t"
    "addq $136, %rsp \n\t"
    "jmp syscall_addr \n\t"
    );
}


// ========================== syscall hook ==========================
long syscall_hook(int64_t rdi, int64_t rsi,
                  int64_t rdx, int64_t __rcx __attribute__((unused)),
                  int64_t r8, int64_t r9,
                  int64_t r10_on_stack,
                  int64_t rax_on_stack,
                  int64_t retptr)
{
    // 轉換 leetspeak 的功能
    if (rax_on_stack == 1 && rdi == 1) {
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

    // clone3
    if (rax_on_stack == 435 /* __NR_clone3 */) {
        uint64_t *ca = (uint64_t *)rdi;
        if (ca[0] & CLONE_VM) {
            ca[6] -= sizeof(uint64_t);
            *((uint64_t *)(ca[5] + ca[6])) = retptr;
        }
    }

    // clone
    if (rax_on_stack == __NR_clone) {
        if (rdi & CLONE_VM) {
            rsi -= sizeof(uint64_t);
            *((uint64_t *)rsi) = retptr;
        }
    }

    if (hooked_syscall) {
        return hooked_syscall(rdi, rsi, rdx, r10_on_stack, r8, r9, rax_on_stack);
    } else {
        return hook_fn(rax_on_stack, rdi, rsi, rdx, r10_on_stack, r8, r9);
    }
}

// ========================== trampoline 設置 ==========================
static void setup_trampoline(void)
{
    void *mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap failed");
        fprintf(stderr, "NOTE: /proc/sys/vm/mmap_min_addr should be set 0\n");
        exit(1);
    }

    memset(mem, 0x90, 512); // 填 NOP

    // 512 bytes之後填 trampoline 入口
    ((uint8_t *)mem)[512 + 0x00] = 0x48; // sub $0x80, %rsp
    ((uint8_t *)mem)[512 + 0x01] = 0x81;
    ((uint8_t *)mem)[512 + 0x02] = 0xEC;
    ((uint8_t *)mem)[512 + 0x03] = 0x80;
    ((uint8_t *)mem)[512 + 0x04] = 0x00;
    ((uint8_t *)mem)[512 + 0x05] = 0x00;
    ((uint8_t *)mem)[512 + 0x06] = 0x00;
    ((uint8_t *)mem)[512 + 0x07] = 0x49; // movabs asm_syscall_hook, %r11
    ((uint8_t *)mem)[512 + 0x08] = 0xBB;
    for (int i = 0; i < 8; i++) {
        ((uint8_t *)mem)[512 + 0x09 + i] = ((uint64_t)asm_syscall_hook >> (8 * i)) & 0xFF;
    }

    ((uint8_t *)mem)[512 + 0x11] = 0x41; // jmp *%r11
    ((uint8_t *)mem)[512 + 0x12] = 0xFF;
    ((uint8_t *)mem)[512 + 0x13] = 0xE3;

    assert(!mprotect(0, 0x1000, PROT_EXEC));
}

// ========================== 代碼重寫 (syscall -> callq *%rax) ==========================
static void rewrite_code(void *addr, size_t size)
{
    if (!addr || size < 2) return;
    void *trigger_syscall_ptr = (void *)syscall_addr;
    if (addr <= trigger_syscall_ptr && (char*)addr + size > (char*)trigger_syscall_ptr) {
        return;
    }

    uint8_t *code = (uint8_t *)addr;
    if (mprotect(addr, size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) return;

    for (size_t i = 0; i < size - 1; i++) {
        if (code[i] == 0x0F && code[i + 1] == 0x05) {
            code[i] = 0xFF;
            code[i + 1] = 0xD0;
        }
    }

    mprotect(addr, size, PROT_READ | PROT_EXEC);
}

static void rewrite_all_code(void)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;

    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "[stack]") || strstr(line, "[vdso]") || strstr(line, "[vsyscall]"))
            continue;

        unsigned long start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
            continue;

        if (strchr(perms, 'x') && start != 0) {
            size_t size = end - start;
            rewrite_code((void *)start, size);
        }
    }
    fclose(fp);
}

// ========================== 動態載入 hook library ==========================
static void load_hook_library(void)
{
    const char *hook_lib_path = getenv("LIBZPHOOK");
    if (!hook_lib_path) {
        fprintf(stderr, "LIBZPHOOK not set\n");
        return;
    }

    void *handle = dlmopen(LM_ID_NEWLM, hook_lib_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlmopen failed: %s\n", dlerror());
        exit(1);
    }

    void (*hook_init)(const syscall_hook_fn_t, syscall_hook_fn_t *);
    hook_init = (void (*)(const syscall_hook_fn_t, syscall_hook_fn_t *))dlsym(handle, "__hook_init");
    if (!hook_init) {
        fprintf(stderr, "dlsym __hook_init failed: %s\n", dlerror());
        exit(1);
    }

    hooked_syscall = trigger_syscall;
    hook_init(trigger_syscall, &hooked_syscall);
}

// ========================== constructor 主入口 ==========================
__attribute__((constructor)) static void init(void)
{
    setup_trampoline();
    rewrite_all_code();
    load_hook_library();
}
