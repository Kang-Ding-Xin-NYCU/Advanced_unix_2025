#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

/*
 * 设置跳板（trampoline）
 * 该跳板会设置在地址0处，并在被调用时打印"Hello from trampoline!"
 */
static void setup_trampoline(void)
{
    // 在虚拟地址0分配内存
    void *mem = mmap(0, 0x1000,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
                     -1, 0);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "Failed to map memory at address 0\n");
        fprintf(stderr, "NOTE: /proc/sys/vm/mmap_min_addr should be set to 0\n");
        exit(1);
    }

    // 填充前512字节为NOP（0x90）
    memset(mem, 0x90, 512);

    // 从512字节处开始放置我们的代码
    // 我们将使用 write 系统调用来打印消息
    unsigned char *code = (unsigned char *)mem + 512;
    
    // 准备要输出的消息
    const char message[] = "Hello from trampoline!\n";
    size_t message_len = strlen(message);
    
    // 将消息复制到跳板内存中
    char *message_ptr = (char *)mem + 600; // 留出一些空间
    memcpy(message_ptr, message, message_len);
    
    // 开始构建汇编代码
    // mov $1, %rax (write系统调用号)
    *code++ = 0x48;
    *code++ = 0xc7;
    *code++ = 0xc0;
    *code++ = 0x01;
    *code++ = 0x00;
    *code++ = 0x00;
    *code++ = 0x00;
    
    // mov $1, %rdi (文件描述符: stdout)
    *code++ = 0x48;
    *code++ = 0xc7;
    *code++ = 0xc7;
    *code++ = 0x01;
    *code++ = 0x00;
    *code++ = 0x00;
    *code++ = 0x00;
    
    // mov $message_ptr, %rsi (消息缓冲区指针)
    *code++ = 0x48;
    *code++ = 0xbe;
    *(uint64_t *)code = (uint64_t)message_ptr;
    code += 8;
    
    // mov $message_len, %rdx (消息长度)
    *code++ = 0x48;
    *code++ = 0xc7;
    *code++ = 0xc2;
    *code++ = message_len;
    *code++ = 0x00;
    *code++ = 0x00;
    *code++ = 0x00;
    
    // syscall (执行系统调用)
    *code++ = 0x0f;
    *code++ = 0x05;
    
    // ret (返回)
    *code++ = 0xc3;
    
    // 确保内存区域是可读和可执行的 
    if (mprotect(mem, 0x1000, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect failed");
        exit(1);
    }
}

__attribute__((constructor)) static void init(void)
{
    setup_trampoline();
}