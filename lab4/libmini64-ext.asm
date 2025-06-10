global time:function
extern sys_gettimeofday

section .text

time:
    sub     rsp, 16           ; 在 stack 上保留 16 bytes，作為 struct timeval 的空間（tv_sec + tv_usec）
    mov     rdi, rsp          ; 第一個參數 rdi = struct timeval*（rdi 指向剛剛保留的空間）
    xor     rsi, rsi          ; 第二個參數 rsi = NULL（不需要 timezone，所以設為 0）
    call    sys_gettimeofday wrt ..plt  
    mov     rax, [rsp]        ; 將 tv.tv_sec 讀到 rax，作為回傳值（以秒為單位的 timestamp）
    add     rsp, 16           ; 還原 stack，釋放剛剛保留的 16 bytes 空間
    ret                       ; 返回呼叫者，rax 中的值就是 time() 的回傳值

global srand:function
global grand:function
global rand:function

section .data
seed dq 0 ; 定義一個 64-bit 全域變數 seed

section .text

srand:
    sub     rdi, 1           ; 只取低 32-bit，清空高位（zero-extension）
    mov     [rel seed], rdi  ; 將傳入的 seed（存在 rdi）儲存到全域變數 seed
    ret

grand:
    mov     rax, [rel seed]  ; 從全域變數 seed 讀出目前的亂數種子
    ret

rand:
    mov     rax, [rel seed]                     ; 將目前的 seed 載入 rax
    mov     rbx, 6364136223846793005            ; 載入乘法用常數（LCG 演算法的 multiplier）
    mul     rbx                                 ; 進行無號乘法：rdx:rax = rax * rbx
    add     rax, 1                              ; 加上 LCG 的 increment 常數（+1）
    mov     [rel seed], rax                     ; 將新的 seed 存回全域變數（只用低 64 位）
    mov     rdx, rax                            ; 將結果複製一份到 rdx 用於右移
    shr     rdx, 33                             ; 將 seed >> 33（產生亂數輸出）
    mov     rax, rdx                            ; 回傳值放入 rax
    ret                                         ; 返回呼叫者（結果是 rand() 回傳的整數）

global sigemptyset:function
global sigfillset:function
global sigaddset:function
global sigdelset:function
global sigismember:function

sigemptyset:
    mov     qword [rdi], 0 ; 將 set 中的 32-bit 整數設為 0（全部清除）
    xor     eax, eax       ; return 0
    ret

sigfillset:
    mov     qword [rdi], 0xFFFFFFFF ; 將 set 設為全 1（表示所有 signal 都存在）
    xor     eax, eax                ; return 0
    ret

sigaddset:
    mov     eax, 1             ; eax = 1，準備要設定 bit
    mov     ecx, esi           ; ecx = signo（shift 數）
    sub     ecx, 1
    shl     eax, cl            ; eax <<= signo（把第 signo 位變成 1）
    or      [rdi], eax         ; set |= 1 << signo（把對應 bit 設為 1）
    xor     eax, eax           ; return 0
    ret

sigdelset:
    mov     eax, 1             ; eax = 1
    mov     ecx, esi           ; ecx = signo
    sub     ecx, 1
    shl     eax, cl            ; eax = (1 << signo)
    not     eax                ; eax = ~(1 << signo)
    and     [rdi], eax         ; set &= ~(1 << signo)（清除對應的 bit）
    xor     eax, eax           ; return 0
    ret

sigismember:
    mov     eax, 1             ; eax = 1
    mov     ecx, esi           ; ecx = signo
    sub     ecx, 1
    shl     eax, cl            ; eax = (1 << signo)
    mov     edx, [rdi]         ; edx = *set
    and     eax, edx           ; eax = (*set) & (1 << signo)
    setnz   al                 ; al = (eax != 0) ? 1 : 0
    movzx   eax, al            ; zero-extend al 成為 int 回傳
    ret

global sigprocmask:function

sigprocmask:
    mov rax, 14              ; rt_sigprocmask 系统调用号
    mov r10, 8               ; sigsetsize = 8
    syscall
    ret

global setjmp:function

section .text

setjmp:
    ; 保存 jmp_buf 的 rdi
    mov r8, rdi            ; 把 rdi 複製到 r8，之後都用 r8，保護 rdi

    ; 保存寄存器到 jmp_buf
    mov [r8 + 0], rbx
    mov [r8 + 8], rbp
    lea rax, [rsp]
    add rax, 8
    mov [r8 + 16], rax
    mov [r8 + 24], r12
    mov [r8 + 32], r13
    mov [r8 + 40], r14
    mov [r8 + 48], r15

    ; 保存 return address
    mov rax, [rsp]
    mov [r8 + 56], rax

    ; 保存 signal mask
    sub rsp, 16                ; 開 16 bytes 空間
    mov rdi, 0                 ; how = 0
    mov rsi, 0                 ; newset = NULL
    lea rdx, [rsp]             ; oldset = rsp
    mov rax, 14              ; rt_sigprocmask 系统调用号
    mov r10, 8               ; sigsetsize = 8
    syscall

    ; 把 signal mask 存到 jmp_buf
    mov rax, [rsp]             ; 抓 signal mask
    mov [r8 + 64], rax         ; 存到 env[8]

    add rsp, 16                ; 還原 stack

    xor eax, eax
    ret

global longjmp:function

section .text

longjmp:
    ; rdi = env pointer (jmp_buf)
    ; esi = value to return

    ; 先恢复 signal mask
    sub rsp, 16                ; 开 16 bytes 空间
    mov rax, [rdi + 64]        ; 读取 env[8]，signal mask
    mov [rsp], rax             ; 把 mask 放到 stack 上

    push rdi                   ; 保存 jmp_buf 指针
    push rsi                   ; 保存返回值
    
    mov edi, 2                 ; how = SIG_SETMASK (2)
    lea rsi, [rsp + 16]        ; newset = &mask (注意栈上多了两个保存的值)
    xor edx, edx               ; oldset = NULL
    mov rax, 14                ; rt_sigprocmask 系统调用号
    mov r10, 8                 ; sigsetsize = 8
    syscall

    pop rsi                    ; 恢复返回值
    pop rdi                    ; 恢复 jmp_buf 指针
    
    add rsp, 16                ; 还原 stack

    ; 恢复寄存器
    mov rbx, [rdi + 0]
    mov rbp, [rdi + 8]
    mov r12, [rdi + 24]
    mov r13, [rdi + 32]
    mov r14, [rdi + 40]
    mov r15, [rdi + 48]
    
    ; 设定 return value
    mov eax, esi
    test eax, eax
    jnz .return_val_ok
    mov eax, 1        ; 如果原本是0，必须改成1
.return_val_ok:

    ; 获取返回地址
    mov rdx, [rdi + 56]        ; 保存的返回地址
    
    ; 恢复栈指针 (必须放在最后一步)
    mov rsp, [rdi + 16]        ; 恢复 rsp
    
    ; 跳到保存的地址
    jmp rdx                    ; 直接跳回原本的地方
