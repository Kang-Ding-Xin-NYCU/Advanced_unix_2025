#include <assert.h>
#include <capstone/capstone.h>  // 反組譯庫，用於將機器碼轉換為組合語言
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>         // 程序追蹤介面，核心功能
#include <sys/types.h>
#include <sys/user.h>           // user_regs_struct 結構定義
#include <sys/wait.h>
#include <unistd.h>
#include <elf.h>                // ELF 檔案格式定義
#include <fcntl.h>              // 檔案操作

#define maxLength 1024

// === 全域變數定義 ===
char programPath[maxLength] = "";     // 目標程式路徑
char cmdLine[maxLength] = "";         // 輸入的命令列
char cmd[4][maxLength];               // 分割後的命令參數（最多4個）
pid_t childPid;                       // 子程序（被除錯程式）的 PID
struct user_regs_struct regs;         // 暫存器狀態結構
static csh cshandle = 0;              // Capstone 反組譯器控制碼
long long breaklist[maxLength][2];    // 斷點列表：[地址, 原始位元組值]
long long breaking = 0;               // 目前命中的斷點地址
long long entry_point;                // 程式進入點地址
int enter = 0x01;                     // 系統呼叫狀態標誌（進入/離開）
long long base_address = 0;           // PIE 程式的基底地址
/**
 * 檢查地址是否有效（可讀寫）
 * @param addr 要檢查的地址
 * @param len  檢查的長度
 * @return 1=有效, 0=無效
 */
int is_valid_addr(unsigned long long addr, size_t len) {
    char path[64]; 
    sprintf(path, "/proc/%d/maps", childPid);  // 讀取程序記憶體映射
    FILE *fp = fopen(path, "r"); 
    if (!fp) return 0;

    unsigned long long start, end; 
    char perm[8], buf[512];
    
    // 解析 /proc/PID/maps 檔案內容
    while (fgets(buf, sizeof(buf), fp)) {
        if (sscanf(buf, "%llx-%llx %7s", &start, &end, perm) == 3) {
            // 檢查地址範圍是否在某個記憶體區段內
            if (addr >= start && addr + len <= end) {
                fclose(fp); 
                return 1;
            }
        }
    }
    fclose(fp); 
    return 0;
}
/**
 * 檢查地址是否為可執行區域
 * @param addr 要檢查的地址
 * @param len  檢查的長度
 * @return 1=可執行, 0=不可執行
 */
int is_exec_addr(unsigned long long addr, size_t len) {
    char path[64]; 
    sprintf(path, "/proc/%d/maps", childPid);
    FILE *fp = fopen(path, "r"); 
    if (!fp) return 0;

    unsigned long long start, end; 
    char perm[8], buf[512];
    
    while (fgets(buf,sizeof(buf),fp)) {
        if (sscanf(buf,"%llx-%llx %7s",&start,&end,perm) == 3) {
            // 必須在範圍內且權限包含執行權限 (x)
            if (addr >= start && addr + len <= end && strchr(perm,'x')) {
                fclose(fp); 
                return 1;
            }
        }
    }
    fclose(fp); 
    return 0;
}

static int memfd = -1;
unsigned char safe_read_byte(unsigned long long addr) {
    if (memfd == -1) {                        // 只開一次
        char path[64];
        sprintf(path, "/proc/%d/mem", childPid);
        memfd = open(path, O_RDONLY);
    }
    unsigned char b;
    if (pread(memfd, &b, 1, addr) == 1)       // 直接從 /proc/PID/mem 讀
        return b;

    /* 後備：再試一次 ptrace（對齊讀 8 bytes） */
    unsigned long long aligned = addr & ~7ULL;
    long word = ptrace(PTRACE_PEEKDATA, childPid, aligned, NULL);
    return ((unsigned char*)&word)[addr & 7ULL];
}
/**
 * 取得 PIE (Position Independent Executable) 程式的基底地址
 * @return 基底地址，失敗返回 0
 */
long long get_base_address() {
    if (base_address) return base_address;  // 已快取則直接返回

    char maps[64]; 
    sprintf(maps, "/proc/%d/maps", childPid);
    FILE *fp = fopen(maps, "r"); 
    if (!fp) return 0;

    unsigned long long start, end; 
    char perm[8], path[512];
    
    // 從程式路徑取得執行檔名稱
    char *bin = strrchr(programPath, '/');
    bin = bin ? bin + 1 : programPath;

    // 在記憶體映射中尋找對應的執行檔映射
    while (fscanf(fp, "%llx-%llx %7s %*s %*s %*s %511s",
                  &start, &end, perm, path) >= 4) {
        if (strstr(path, bin)) {                    // 路徑對得上
            if (base_address == 0 || start < base_address)
                base_address = start;               // 記錄最小的起始地址
        }
    }
    fclose(fp);

    // 備用方案：如果無法取得，用 entry_point 推算
    if (!base_address && entry_point > 0x1080)
        base_address = entry_point - 0x1080;

    return base_address;
}
/**
 * 處理 breakrva 命令：設置相對於基底地址的斷點
 * 格式：breakrva [hex offset]
 */
void cmd_break_rva() {
    unsigned long long int offset = strtoull(cmd[1], NULL, 16);
    long long base = get_base_address();
    
    if (base == 0) {
        printf("** the target address is not valid.\n");
        return;
    }
    
    // 計算絕對地址 = 基底地址 + 偏移
    unsigned long long int addr = base + offset;
    if (!is_valid_addr(addr, 1)) {
        printf("** the target address is not valid.\n");
        return;
    }
    
    // 嘗試讀取該地址以確認有效性
    unsigned char orig = safe_read_byte(addr);
    errno = 0;
    if (errno != 0) {
        printf("** the target address is not valid.\n");
        return;
    }
    
    // 在斷點列表中找空位並記錄斷點資訊
    for (int i = 0; i < maxLength; i++) {
        if (!breaklist[i][0] && !breaklist[i][1]) {
            breaklist[i][0] = addr;                 // 斷點地址
            breaklist[i][1] = orig;          // 原始位元組
            break;
        }
    }
    
    // 設置 int3 斷點（0xcc）
    unsigned long long word_addr = addr & ~7ULL;
    long data = ptrace(PTRACE_PEEKDATA, childPid, word_addr, NULL);
    ((unsigned char*)&data)[addr & 7ULL] = 0xcc;
    ptrace(PTRACE_POKEDATA, childPid, word_addr, data);
    
    printf("** set a breakpoint at 0x%llx.\n", addr);
}
/**
 * 分割輸入命令為參數陣列
 */
void cmd_slice() {
    // 移除換行符號
    if (cmdLine[strlen(cmdLine) - 1] == '\n') {
        cmdLine[strlen(cmdLine) - 1] = '\0';
    }
    
    char *token;
    int i = 0;
    token = strtok(cmdLine, " ");
    while (token != NULL) {
        if (i >= 4) break;  // 最多4個參數
        strcpy(cmd[i], token);
        i++;
        token = strtok(NULL, " ");
    }
}
/**
 * 重新設置所有斷點（除了目前命中的）
 * 在執行指令前呼叫，確保斷點有效
 */
void break_in() {
    for (int i = 0; i < maxLength; i++) {
        if (!breaklist[i][0]) break;
        
        // 跳過目前正在處理的斷點，避免重複觸發
        if (breaking && breaklist[i][0] == breaking) {
            continue;
        }
        
        // 重新設置 int3 斷點
        //ptrace(PTRACE_PEEKDATA, childPid, breaklist[i][0], NULL);
        long data = ptrace(PTRACE_PEEKDATA, childPid, breaklist[i][0], NULL);
        data = (data & 0xffffffffffffff00) | 0xcc;
        ptrace(PTRACE_POKEDATA, childPid, breaklist[i][0], data);
    }
}
/**
 * 暫時移除所有斷點，恢復原始指令
 * 在反組譯時呼叫，確保顯示正確的指令內容
 */
void break_out() {
    for (int i = 0; i < maxLength; i++) {
        if (breaklist[i][0]) {
            // 恢復原始位元組
            unsigned long long addr = breaklist[i][0];
            unsigned long long word_addr = addr & ~7ULL;

            long data = ptrace(PTRACE_PEEKDATA, childPid, word_addr, NULL);
            unsigned char *p = (unsigned char*)&data;
            p[addr & 7ULL] = (unsigned char)breaklist[i][1];   // 正確原 byte
            ptrace(PTRACE_POKEDATA, childPid, word_addr, data);
        }
    }
}
/**
 * 反組譯並顯示目前指令位置的 5 條指令
 * 這是除錯器的核心顯示功能
 */
void disassemble() {
    static int memfd = -1;

    break_out();
    cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle);

    int addr_offset = 0;
    ptrace(PTRACE_GETREGS, childPid, NULL, &regs);

    for (int printed = 0; printed < 5; ) {
        unsigned long long cur = regs.rip + addr_offset;

        /* 計算這段可執行長度 (<=32) */
        size_t need = 0;
        while (need < 32 && is_exec_addr(cur + need, 1))
            ++need;
        if (need == 0) {
            // 檢查程式是否還在執行
            int status;
            pid_t result = waitpid(childPid, &status, WNOHANG);
            if (result != 0 || kill(childPid, 0) == -1) {
                // 程式已經終止，不要輸出錯誤訊息
                break;
            }
            
            puts("** the address is out of the range of the executable region.");
            break;
        }

        /* 一口氣讀進來 */
        unsigned char buf[32];
        if (memfd == -1) {
            char mempath[64];
            sprintf(mempath, "/proc/%d/mem", childPid);
            memfd = open(mempath, O_RDONLY);
        }
        if (pread(memfd, buf, need, cur) < 1) {
            puts("** failed to read target memory.");
            break;
        }

        /* 交給 Capstone */
        cs_insn *insn;
        size_t n = cs_disasm(cshandle, buf, need, cur, 1, &insn);
        if (n == 0) {                 /* 解不出來就往前滑 1 byte */
            addr_offset += 1;
            continue;
        }

        /* 正常輸出一條指令 - 修正格式：移除前導空格和多餘對齊 */
        printf("%llx: ", insn[0].address);                    // 地址，無前導空格
        for (int k = 0; k < insn[0].size; ++k) {              // 只輸出實際的位元組
            printf("%02x ", buf[k]);
        }
        printf("%s", insn[0].mnemonic);                       // 助記符
        if (strlen(insn[0].op_str) > 0) {                     // 操作數（如果有）
            printf(" %s", insn[0].op_str);
        }
        printf("\n");

        addr_offset += insn[0].size;
        ++printed;
        cs_free(insn, n);
    }

    cs_close(&cshandle);
    break_in();
}
/**
 * 載入目標程式
 * 格式：load [program_path]
 */
void cmd_load() {
    // 創建子程序執行目標程式
    childPid = fork();
    if (childPid == 0) {
        // 子程序：啟用追蹤並執行目標程式
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execl(programPath, programPath, NULL);
    } else {
        // 父程序：等待子程序停止並設置追蹤選項
        int status;  
        waitpid(childPid, &status, 0);
        assert(WIFSTOPPED(status));

        // 設置追蹤選項：程序結束時自動殺死子程序，系統呼叫追蹤
        ptrace(PTRACE_SETOPTIONS, childPid, 0,
                PTRACE_O_EXITKILL |            /* 子行程 crash 時一起殺掉 */
                PTRACE_O_TRACESYSGOOD |        /* syscall-stop 加 0x80 */
                PTRACE_O_TRACEEXIT);           /* <<<<<< 新增：收到 EXIT-stop */
        // 取得初始暫存器狀態
        ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
        entry_point = regs.rip;

        // 讀取 ELF 標頭以取得真正的進入點
        Elf64_Ehdr ehdr;
        int fd = open(programPath, O_RDONLY);
        read(fd, &ehdr, sizeof(ehdr));
        close(fd);

        long long base = get_base_address();
        unsigned long long real_entry;
        
        // 計算真正的進入點地址
        if (ehdr.e_type == ET_EXEC) {
            // 靜態連結程式
            real_entry = ehdr.e_entry;
        } else {
            // 動態連結或 PIE 程式
            real_entry = base + ehdr.e_entry;
        }

        // 如果目前還在動態連結器，需要設置斷點跳到程式進入點
        if (regs.rip != real_entry) {
            long orig = ptrace(PTRACE_PEEKDATA, childPid, real_entry, 0);
            ptrace(PTRACE_POKEDATA, childPid, real_entry, 
                   (orig & 0xffffffffffffff00) | 0xcc);

            ptrace(PTRACE_CONT, childPid, 0, 0);
            waitpid(childPid, &status, 0);

            // 恢復原始指令並設置正確的 RIP
            ptrace(PTRACE_POKEDATA, childPid, real_entry, orig);
            ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
            regs.rip = real_entry;
            ptrace(PTRACE_SETREGS, childPid, NULL, &regs);
        }

        entry_point = regs.rip;
        printf("** program '%s' loaded. entry point: 0x%llx.\n", programPath, regs.rip);
        disassemble();
    }
}
/**
 * 單步執行一條指令
 * 格式：si
 */
void cmd_si() {
    // 如果在進入點且有斷點，先恢復原始指令
    if (entry_point == regs.rip) {
        for (int i = 0; i < maxLength; i++) {
            if (breaklist[i][0] == entry_point) {
                long data = ptrace(PTRACE_PEEKDATA, childPid, entry_point, NULL);
                data = (data & 0xffffffffffffff00) | (breaklist[i][1]);
                ptrace(PTRACE_POKEDATA, childPid, entry_point, data);
                breaking = entry_point;
            }
        }
    }
    
    // 執行單步
    ptrace(PTRACE_SINGLESTEP, childPid, NULL, NULL);
    int status;
    waitpid(childPid, &status, 0);
    
    if (WIFEXITED(status)) {
        // 程式結束
        printf("** the target program terminated.\n");
        strcpy(programPath, "");
    } else if (WIFSTOPPED(status)) {
        // 程式停止，檢查是否命中斷點
        ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
        for (int i = 0; i < maxLength; i++) {
            if ((breaklist[i][0] == regs.rip)) {
                if (breaking == regs.rip) break;  // 避免重複報告
                printf("** hit a breakpoint at 0x%llx.\n", regs.rip);
                breaking = regs.rip;
                break;
            } else {
                breaking = 0;
            }
        }
        disassemble();
    }
}
/**
 * 繼續執行直到命中斷點或程式結束
 * 格式：cont
 */
void cmd_cont() {
    // 如果目前在斷點上，先單步跳過再繼續
    if (breaking) {
        ptrace(PTRACE_SINGLESTEP, childPid, NULL, NULL);
        int status1;
        waitpid(childPid, &status1, 0);
        
        if (WIFEXITED(status1)) {
            printf("** the target program terminated.\n");
            strcpy(programPath, "");
            return;
        }
        
        // 重新設置斷點
        long data = ptrace(PTRACE_PEEKDATA, childPid, breaking, NULL);
        data = (data & 0xffffffffffffff00) | 0xcc;
        ptrace(PTRACE_POKEDATA, childPid, breaking, data);
        breaking = 0;
    }
    
    // 繼續執行
    ptrace(PTRACE_CONT, childPid, 0, 0);
    int status;
    waitpid(childPid, &status, 0);

    // 處理 PTRACE_EVENT_EXIT
    if (WIFSTOPPED(status) && 
        WSTOPSIG(status) == SIGTRAP &&
        ((status >> 16) == PTRACE_EVENT_EXIT)) {
        printf("** the target program terminated.\n");
        ptrace(PTRACE_CONT, childPid, 0, 0);
        waitpid(childPid, &status, 0);
        programPath[0] = '\0';
        return;
    }

    if (WIFEXITED(status)) {
        printf("** the target program terminated.\n");
        strcpy(programPath, "");
        return;
    } 
    
    if (WIFSTOPPED(status)) {
        ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
        
        // 檢查是否命中斷點
        int hit_breakpoint = 0;
        for (int i = 0; i < maxLength; i++) {
            if ((breaklist[i][0] == regs.rip - 1) && (breaking != regs.rip - 1)) {
                printf("** hit a breakpoint at 0x%llx.\n", --regs.rip);
                ptrace(PTRACE_SETREGS, childPid, NULL, &regs);
                breaking = regs.rip;
                hit_breakpoint = 1;
                disassemble();
                return;
            }
        }
        
        if (!hit_breakpoint) {
            breaking = 0;
            // 新增：檢查是否是因為執行了無效地址
            // 如果是 SIGSEGV 或其他錯誤信號，視為程式終止
            if (WSTOPSIG(status) == SIGSEGV || 
                WSTOPSIG(status) == SIGILL ||
                !is_exec_addr(regs.rip, 1)) {
                
                // 再次嘗試繼續執行，讓程式真正終止
                ptrace(PTRACE_CONT, childPid, 0, 0);
                waitpid(childPid, &status, 0);
                
                printf("** the target program terminated.\n");
                strcpy(programPath, "");
                return;
            }
            disassemble();
        }
    }
}
/**
 * 顯示所有暫存器的值
 * 格式：info reg
 */
void cmd_info_reg() {
    printf("$rax 0x%016llx    $rbx 0x%016llx    $rcx 0x%016llx\n", 
           regs.rax, regs.rbx, regs.rcx);
    printf("$rdx 0x%016llx    $rsi 0x%016llx    $rdi 0x%016llx\n", 
           regs.rdx, regs.rsi, regs.rdi);
    printf("$rbp 0x%016llx    $rsp 0x%016llx    $r8  0x%016llx\n", 
           regs.rbp, regs.rsp, regs.r8);
    printf("$r9  0x%016llx    $r10 0x%016llx    $r11 0x%016llx\n", 
           regs.r9, regs.r10, regs.r11);
    printf("$r12 0x%016llx    $r13 0x%016llx    $r14 0x%016llx\n", 
           regs.r12, regs.r13, regs.r14);
    printf("$r15 0x%016llx    $rip 0x%016llx    $eflags 0x%016llx\n", 
           regs.r15, regs.rip, regs.eflags);
}
/**
 * 顯示所有斷點資訊
 * 格式：info break
 */
void cmd_info_break() {
    int flag = 0;
    for (int i = 0; i < maxLength; i++) {
        if (breaklist[i][0]) {
            if (!flag++) {
                printf("Num     Address\n");
            }
            printf("%d       0x%llx\n", i, breaklist[i][0]);
        }
    }
    if (!flag) {
        printf("** no breakpoints.\n");
    }
}
/**
 * 設置斷點
 * 格式：break [hex_address]
 */
void cmd_break_point() {
    unsigned long long int addr = strtoull(cmd[1], NULL, 16);
    unsigned char orig = safe_read_byte(addr);
    errno = 0;
    
    if (!is_valid_addr(addr, 1)) {
        printf("** the target address is not valid.\n");
        return;
    }
    
    // 在斷點列表中找空位
    for (int i = 0; i < maxLength; i++) {
        if (!breaklist[i][0] && !breaklist[i][1]) {
            breaklist[i][0] = addr;                 // 斷點地址
            breaklist[i][1] = orig;          // 原始位元組
            break;
        }
    }
    
    // 設置 int3 斷點
    unsigned long long word_addr = addr & ~7ULL;
    long data = ptrace(PTRACE_PEEKDATA, childPid, word_addr, NULL);
    ((unsigned char*)&data)[addr & 7ULL] = 0xcc;
    ptrace(PTRACE_POKEDATA, childPid, word_addr, data);
    printf("** set a breakpoint at 0x%llx.\n", addr);
}
/**
 * 刪除指定編號的斷點
 * 格式：delete [id]
 */
void cmd_delete_break_point() {
    if (breaklist[atoi(cmd[1])][0]) {
        // 恢復原始指令
        long data = ptrace(PTRACE_PEEKDATA, childPid, breaklist[atoi(cmd[1])][0], NULL);
        data = (data & 0xffffffffffffff00) | (breaklist[atoi(cmd[1])][1]);
        ptrace(PTRACE_POKEDATA, childPid, breaklist[atoi(cmd[1])][0], data);
        
        // 如果刪除的是目前命中的斷點，清除狀態
        if (breaking == breaklist[atoi(cmd[1])][0])
            breaking = 0;
            
        breaklist[atoi(cmd[1])][0] = 0;
        printf("** delete breakpoint %d.\n", atoi(cmd[1]));
    } else {
        printf("** breakpoint %d does not exist.\n", atoi(cmd[1]));
    }
}
/**
 * 修改記憶體內容
 * 格式：patch [hex_address] [hex_string]
 */
void cmd_patch_memory() {
    break_out();                                    // 先移除斷點以免干擾

    unsigned long long addr = strtoull(cmd[1], NULL, 16);
    char *hex = cmd[2];
    size_t nbyte = strlen(hex) / 2;                 // 位元組數

    // 輸入驗證
    if (strlen(hex) == 0 || strlen(hex) > 2048 || strlen(hex) % 2 != 0
        || !is_valid_addr(addr, nbyte)) {
        printf("** the target address is not valid.\n");
        break_in(); 
        return;
    }

    // 逐位元組寫入
    for (size_t i = 0; i < nbyte; ++i) {
        char byte_str[3] = { hex[i*2], hex[i*2+1], '\0' };
        unsigned char val = strtoul(byte_str, NULL, 16);

        // ptrace 只能以 8-byte word 為單位操作
        unsigned long long word_addr = (addr + i) & ~7ULL;     // 8-byte 對齊
        int byte_off = (addr + i) & 7ULL;                      // 在 word 中的偏移

        unsigned long data = ptrace(PTRACE_PEEKDATA, childPid, word_addr, NULL);
        unsigned char *p = (unsigned char*)&data; 
        p[byte_off] = val;                                     // 修改對應位元組
        ptrace(PTRACE_POKEDATA, childPid, word_addr, data);
    }

    printf("** patch memory at 0x%llx.\n", addr);
    break_in();                                     // 重新設置斷點
}
/**
 * 系統呼叫追蹤
 * 格式：syscall
 */
void cmd_syscall() {
    static int in_exit_syscall = 0;  // 追蹤是否剛進入 exit syscall
    
    ptrace(PTRACE_SYSCALL, childPid, 0, 0);        // 在系統呼叫處停止
    int status;
    waitpid(childPid, &status, 0);
    
    if (WIFEXITED(status)) {
        printf("** the target program terminated.\n");
        strcpy(programPath, "");
        return;
    } 
    
    if (WIFSTOPPED(status)) {
        ptrace(PTRACE_GETREGS, childPid, NULL, &regs);
        
        if (WSTOPSIG(status) & 0x80) {              // 系統呼叫相關停止
            if (enter) {
                // 進入系統呼叫：RIP 指向 syscall 指令後
                regs.rip -= 2;
                ptrace(PTRACE_SETREGS, childPid, NULL, &regs);
                printf("** enter a syscall(%lld) at 0x%llx.\n", 
                       regs.orig_rax, regs.rip);
                
                // 記錄是否進入 exit syscall
                if (regs.orig_rax == 60) {
                    in_exit_syscall = 1;
                }
            } else {
                // 離開系統呼叫：顯示返回值
                printf("** leave a syscall(%lld) = %lld at 0x%llx.\n", 
                       regs.orig_rax, regs.rax, regs.rip);
                in_exit_syscall = 0;  // 清除標記
            }
            enter ^= 0x01;                          // 切換進入/離開狀態
        } else {
            // 不是系統呼叫相關停止
            // 如果剛剛進入過 exit syscall，現在程式可能已經終止
            if (in_exit_syscall) {
                printf("** the target program terminated.\n");
                strcpy(programPath, "");
                return;
            }
            
            // 命中斷點
            for (int i = 0; i < maxLength; i++) {
                if ((breaklist[i][0] == regs.rip - 1) && (breaking != regs.rip - 1)) {
                    printf("** hit a breakpoint at 0x%llx.\n", --regs.rip);
                    ptrace(PTRACE_SETREGS, childPid, NULL, &regs);
                    breaking = regs.rip;
                    break;
                } else {
                    breaking = 0;
                }
            }
        }
        
        disassemble();
        
        // 系統呼叫進入後需要調整 RIP
        if (WSTOPSIG(status) & 0x80 && enter) {
            regs.rip += 2;
            ptrace(PTRACE_SETREGS, childPid, NULL, &regs);
        }
    }
}
/**
 * 主要的命令處理迴圈
 */
void exec_sdb() {
    // 初始化斷點列表
    for (int i = 0; i < maxLength; i++) {
        breaklist[i][0] = 0;
        breaklist[i][1] = 0;
    }
    
    // 主命令迴圈
    while (1) {
        printf("(sdb) ");
        fgets(cmdLine, maxLength, stdin);
        cmd_slice();
        
        // 檢查是否已載入程式
        if (!strcmp(programPath, "") && strcmp(cmd[0], "load")) {
            printf("** please load a program first.\n");
            continue;
        }
        
        // 命令分派
        if (!strcmp(cmd[0], "load")) {
            strcpy(programPath, cmd[1]);
            cmd_load();
        } else if (!strcmp(cmd[0], "si")) {
            cmd_si();
        } else if (!strcmp(cmd[0], "cont")) {
            cmd_cont();
        } else if (!strcmp(cmd[0], "info")) {
            if (!strcmp(cmd[1], "reg")) {
                cmd_info_reg();
            } else if (!strcmp(cmd[1], "break")) {
                cmd_info_break();
            }
        } else if (!strcmp(cmd[0], "break")) {
            cmd_break_point();
        } else if (!strcmp(cmd[0], "breakrva")) {
            cmd_break_rva();
        } else if (!strcmp(cmd[0], "delete")) {
            cmd_delete_break_point();
        } else if (!strcmp(cmd[0], "patch")) {
            cmd_patch_memory();
        } else if (!strcmp(cmd[0], "syscall")) {
            cmd_syscall();
        }
        strcpy(cmd[0], "");
    }
}
/**
 * 主函數
 */
int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);              // 關閉輸出緩衝
    
    if (argc <= 2) {
        if (argc == 2) {
            // 啟動時直接載入程式
            strcpy(programPath, argv[1]);
            cmd_load();
        }
        exec_sdb();
    } else {
        printf("Usage: ./sdb (without any argument)\nUsage: ./sdb [program]\n");
    }
    return 0;
}