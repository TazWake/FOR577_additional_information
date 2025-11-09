; self-check - Small Assembly Trust Beacon for Linux IR
; Version: 0.1-minimal
; Architecture: x86-64 Linux
; Assembler: NASM (Intel syntax)
; Features: Identity, Capabilities, Seccomp detection, Text output only
;
; Build:
;   nasm -felf64 src/self-check.asm -o self-check.o
;   ld -static -nostdlib -o self-check self-check.o
;   strip self-check
;
; Usage:
;   ./self-check
;
; Output: Single-line key=value format
;   pid=X ppid=X uid=X euid=X gid=X egid=X cap_eff=0xXXX cap_prm=0xXXX seccomp=X nonewprivs=X

; ============================================================================
; ASSEMBLER DIRECTIVES
; ============================================================================

; CRITICAL: Use RIP-relative addressing for all memory references
; Without this, [symbol] uses 32-bit absolute addressing, which fails in 64-bit mode
DEFAULT REL

; ============================================================================
; SECTION: Constants and Read-Only Data
; ============================================================================

section .rodata

; File paths
path_proc_status:   db '/proc/self/status', 0
path_proc_status_len equ $ - path_proc_status - 1

; Output field names and formatting
str_pid:           db 'pid=', 0
str_ppid:          db ' ppid=', 0
str_uid:           db ' uid=', 0
str_euid:          db ' euid=', 0
str_gid:          db ' gid=', 0
str_egid:          db ' egid=', 0
str_cap_eff:       db ' cap_eff=0x', 0
str_cap_prm:       db ' cap_prm=0x', 0
str_seccomp:       db ' seccomp=', 0
str_nonewprivs:    db ' nonewprivs=', 0
str_newline:       db 10, 0

; Error messages
err_status_open:   db 'ERROR: Cannot open /proc/self/status', 10, 0
err_status_read:   db 'ERROR: Cannot read /proc/self/status', 10, 0

; /proc/self/status parsing keys
key_cap_eff:       db 'CapEff:', 0
key_cap_prm:       db 'CapPrm:', 0
key_seccomp:       db 'Seccomp:', 0
key_nonewprivs:    db 'NoNewPrivs:', 0

; Syscall numbers (x86-64 Linux)
SYS_read      equ 0
SYS_write     equ 1
SYS_close     equ 3
SYS_getpid    equ 39
SYS_exit      equ 60
SYS_getppid   equ 110
SYS_getuid    equ 102
SYS_geteuid   equ 107
SYS_getgid    equ 104
SYS_getegid   equ 108
SYS_openat    equ 257

; File operation constants
O_RDONLY      equ 0
O_CLOEXEC     equ 0x80000
AT_FDCWD      equ -100

STDOUT        equ 1
STDERR        equ 2

; ============================================================================
; SECTION: Uninitialized Data (BSS)
; ============================================================================

section .bss

; Buffer for /proc/self/status content (4KB should be sufficient)
status_buffer:     resb 4096

; Buffer for formatted output (1KB)
output_buffer:     resb 1024

; Temporary buffer for number-to-string conversion (32 bytes sufficient for 64-bit values)
num_buffer:        resb 32

; ============================================================================
; SECTION: Code
; ============================================================================

section .text
global _start

; ============================================================================
; Entry Point
; ============================================================================

_start:
    ; Set up stack frame (optional for minimal version, but good practice)
    push rbp
    mov rbp, rsp

    ; Initialize output buffer pointer (not used, but kept for clarity)
    ; Output buffer address is loaded in each function as needed

    ; Collect and format identity information
    call collect_identity

    ; Parse /proc/self/status for capabilities and seccomp
    call parse_proc_status

    ; Write newline
    lea rsi, [str_newline]
    call append_string

    ; Write output buffer to stdout
    mov rax, SYS_write
    mov rdi, STDOUT
    lea rsi, [output_buffer]
    mov rdx, [output_pos]
    syscall

    ; Exit successfully
    mov rax, SYS_exit
    xor rdi, rdi          ; exit code 0
    syscall

; ============================================================================
; Module: Identity Collection
; ============================================================================

collect_identity:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; Output buffer pointer is in rdi (from caller)
    mov r15, rdi           ; Save output buffer pointer

    ; Get PID
    mov rax, SYS_getpid
    syscall
    mov r12, rax           ; Save PID

    ; Append "pid="
    lea rsi, [str_pid]
    call append_string

    ; Convert PID to string and append
    mov rdi, r12
    call append_decimal

    ; Get PPID
    mov rax, SYS_getppid
    syscall
    mov r13, rax           ; Save PPID

    ; Append " ppid="
    lea rsi, [str_ppid]
    call append_string

    ; Convert PPID to string and append
    mov rdi, r13
    call append_decimal

    ; Get UID
    mov rax, SYS_getuid
    syscall
    mov r12, rax

    ; Append " uid="
    lea rsi, [str_uid]
    call append_string

    ; Convert UID to string and append
    mov rdi, r12
    call append_decimal

    ; Get EUID
    mov rax, SYS_geteuid
    syscall
    mov r12, rax

    ; Append " euid="
    lea rsi, [str_euid]
    call append_string

    ; Convert EUID to string and append
    mov rdi, r12
    call append_decimal

    ; Get GID
    mov rax, SYS_getgid
    syscall
    mov r12, rax

    ; Append " gid="
    lea rsi, [str_gid]
    call append_string

    ; Convert GID to string and append
    mov rdi, r12
    call append_decimal

    ; Get EGID
    mov rax, SYS_getegid
    syscall
    mov r12, rax

    ; Append " egid="
    lea rsi, [str_egid]
    call append_string

    ; Convert EGID to string and append
    mov rdi, r12
    call append_decimal

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; ============================================================================
; Module: /proc/self/status Parser
; ============================================================================

parse_proc_status:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; Open /proc/self/status
    mov rax, SYS_openat
    mov rdi, AT_FDCWD
    lea rsi, [path_proc_status]
    mov rdx, O_RDONLY
    xor r10, r10           ; mode (not used for read-only)
    syscall

    ; Check for error
    cmp rax, 0
    jl .error_open

    mov r12, rax           ; Save file descriptor

    ; Read file into buffer
    mov rax, SYS_read
    mov rdi, r12
    lea rsi, [status_buffer]
    mov rdx, 4096
    syscall

    ; Check for error
    cmp rax, 0
    jl .error_read

    mov r13, rax           ; Save bytes read

    ; Close file
    mov rax, SYS_close
    mov rdi, r12
    syscall

    ; Parse buffer for CapEff
    lea rdi, [status_buffer]
    mov rsi, r13
    lea rdx, [key_cap_eff]
    call find_key_value
    mov r14, rax           ; Save pointer to value (append_string modifies rax)

    ; Append " cap_eff=0x"
    lea rsi, [str_cap_eff]
    call append_string

    ; Append the capability hex value (r14 contains pointer to value)
    test r14, r14
    jz .cap_eff_zero
    mov rsi, r14
    call append_string_until_newline
    jmp .parse_cap_prm
.cap_eff_zero:
    lea rsi, [.str_zero]
    call append_string

.parse_cap_prm:
    ; Parse buffer for CapPrm
    lea rdi, [status_buffer]
    mov rsi, r13
    lea rdx, [key_cap_prm]
    call find_key_value
    mov r14, rax           ; Save pointer to value

    ; Append " cap_prm=0x"
    lea rsi, [str_cap_prm]
    call append_string

    ; Append the capability hex value
    test r14, r14
    jz .cap_prm_zero
    mov rsi, r14
    call append_string_until_newline
    jmp .parse_seccomp
.cap_prm_zero:
    lea rsi, [.str_zero]
    call append_string

.parse_seccomp:
    ; Parse buffer for Seccomp
    lea rdi, [status_buffer]
    mov rsi, r13
    lea rdx, [key_seccomp]
    call find_key_value
    mov r14, rax           ; Save pointer to value

    ; Append " seccomp="
    lea rsi, [str_seccomp]
    call append_string

    ; Convert value to decimal and append
    test r14, r14
    jz .seccomp_zero
    mov rdi, r14
    call parse_decimal_from_string
    mov rdi, rax
    call append_decimal
    jmp .parse_nonewprivs
.seccomp_zero:
    mov rdi, 0
    call append_decimal

.parse_nonewprivs:
    ; Parse buffer for NoNewPrivs
    lea rdi, [status_buffer]
    mov rsi, r13
    lea rdx, [key_nonewprivs]
    call find_key_value
    mov r14, rax           ; Save pointer to value

    ; Append " nonewprivs="
    lea rsi, [str_nonewprivs]
    call append_string

    ; Convert value to decimal and append
    test r14, r14
    jz .nonewprivs_zero
    mov rdi, r14
    call parse_decimal_from_string
    mov rdi, rax
    call append_decimal
    jmp .done
.nonewprivs_zero:
    mov rdi, 0
    call append_decimal

.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

.error_open:
    ; Write error message to stderr
    mov rax, SYS_write
    mov rdi, STDERR
    lea rsi, [err_status_open]
    mov rdx, 38
    syscall

    ; Exit with code 1
    mov rax, SYS_exit
    mov rdi, 1
    syscall

.error_read:
    ; Close file first
    mov rax, SYS_close
    mov rdi, r12
    syscall

    ; Write error message to stderr
    mov rax, SYS_write
    mov rdi, STDERR
    lea rsi, [err_status_read]
    mov rdx, 38
    syscall

    ; Exit with code 1
    mov rax, SYS_exit
    mov rdi, 1
    syscall

.str_zero: db '0', 0

; ============================================================================
; Module: String and Number Utility Functions
; ============================================================================

; Global variable to track current position in output buffer
section .data
output_pos: dq 0

section .text

; Function: append_string
; Appends a null-terminated string to the output buffer
; Input: rsi = pointer to null-terminated string
; Modifies: rax, rcx, rdi, rsi
append_string:
    push rbp
    mov rbp, rsp
    push rbx

    lea rdi, [output_buffer]
    add rdi, [output_pos]

.loop:
    lodsb                  ; Load byte from [rsi] into al, increment rsi
    test al, al            ; Check if null terminator
    jz .done
    stosb                  ; Store byte from al into [rdi], increment rdi
    jmp .loop

.done:
    ; Update output position
    mov rax, rdi
    lea rbx, [output_buffer]
    sub rax, rbx
    mov [output_pos], rax

    pop rbx
    pop rbp
    ret

; Function: append_string_until_newline
; Appends a string until newline or null terminator, trimming whitespace
; Input: rsi = pointer to string
; Modifies: rax, rcx, rdi, rsi
append_string_until_newline:
    push rbp
    mov rbp, rsp
    push rbx

    ; Skip leading whitespace
.skip_ws:
    lodsb
    cmp al, ' '
    je .skip_ws
    cmp al, 9              ; tab
    je .skip_ws

    ; Start copying
    lea rdi, [output_buffer]
    add rdi, [output_pos]

.loop:
    cmp al, 10             ; newline
    je .done
    cmp al, 13             ; carriage return
    je .done
    test al, al
    jz .done
    stosb
    lodsb
    jmp .loop

.done:
    ; Update output position
    mov rax, rdi
    lea rbx, [output_buffer]
    sub rax, rbx
    mov [output_pos], rax

    pop rbx
    pop rbp
    ret

; Function: append_decimal
; Converts a 64-bit unsigned integer to decimal string and appends to output
; Input: rdi = number to convert
; Modifies: rax, rcx, rdx, rdi, rsi
append_decimal:
    push rbp
    mov rbp, rsp
    push rbx
    push r12

    mov rax, rdi           ; Number to convert
    lea rdi, [num_buffer + 31]
    mov byte [rdi], 0      ; Null terminator
    dec rdi

    mov rcx, 10            ; Divisor

.convert_loop:
    xor rdx, rdx
    div rcx                ; rax = rax / 10, rdx = rax % 10
    add dl, '0'            ; Convert remainder to ASCII
    mov [rdi], dl
    dec rdi
    test rax, rax
    jnz .convert_loop

    ; rdi now points to character before first digit
    inc rdi

    ; Append the string
    mov rsi, rdi
    call append_string

    pop r12
    pop rbx
    pop rbp
    ret

; Function: find_key_value
; Finds a key in the buffer and returns pointer to its value
; Input: rdi = buffer, rsi = buffer length, rdx = key string
; Output: rax = pointer to value (after key and whitespace), or 0 if not found
; Modifies: rax, rbx, rcx, rdx, rsi
find_key_value:
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi           ; Buffer
    mov r13, rsi           ; Buffer length
    mov r14, rdx           ; Key string

    ; Get key length
    mov rdi, r14
    call strlen
    mov r15, rax           ; Key length

    ; Search for key in buffer
    xor rcx, rcx           ; Buffer position

.search_loop:
    cmp rcx, r13
    jge .not_found

    ; Check if we're at start of line
    test rcx, rcx
    jz .check_key
    mov al, [r12 + rcx - 1]
    cmp al, 10
    jne .next_char

.check_key:
    ; Compare key
    mov rsi, r12
    add rsi, rcx
    mov rdi, r14
    mov rbx, r15

.cmp_loop:
    test rbx, rbx
    jz .key_found
    lodsb
    mov ah, [rdi]
    cmp al, ah
    jne .next_char
    inc rdi
    dec rbx
    jmp .cmp_loop

.key_found:
    ; Skip past key and any whitespace/tabs
    add rcx, r15

.skip_whitespace:
    cmp rcx, r13
    jge .not_found
    mov al, [r12 + rcx]
    cmp al, ' '
    je .skip_ws_next
    cmp al, 9              ; tab
    je .skip_ws_next

    ; Found start of value
    lea rax, [r12 + rcx]
    jmp .done

.skip_ws_next:
    inc rcx
    jmp .skip_whitespace

.next_char:
    inc rcx
    jmp .search_loop

.not_found:
    xor rax, rax

.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    ret

; Function: strlen
; Returns length of null-terminated string
; Input: rdi = pointer to string
; Output: rax = length
; Modifies: rax, rcx
strlen:
    push rbp
    mov rbp, rsp

    xor rax, rax
    mov rcx, -1
    xor al, al
    repne scasb
    not rcx
    dec rcx
    mov rax, rcx

    pop rbp
    ret

; Function: parse_decimal_from_string
; Parses decimal number from string
; Input: rdi = pointer to string
; Output: rax = parsed number
; Modifies: rax, rbx, rcx, rdx
parse_decimal_from_string:
    push rbp
    mov rbp, rsp

    xor rax, rax           ; Result
    xor rcx, rcx           ; Digit

.loop:
    movzx rcx, byte [rdi]
    cmp cl, '0'
    jl .done
    cmp cl, '9'
    jg .done

    ; rax = rax * 10 + (cl - '0')
    imul rax, rax, 10
    sub cl, '0'
    add rax, rcx

    inc rdi
    jmp .loop

.done:
    pop rbp
    ret
