[bits 64]

section .code

struc UNICODE_STRING
    .length:     resw 1
    .max_length: resw 1
    .padding:    resb 4
    .ptr:        resq 1
endstruc

struc OBJECT_ATTRIBUTES
    .length:         resd 1
    .padding:        resd 1
    .root_directory: resq 1
    .object_name:    resq 1
    .attributes:     resd 1
    .padding2:       resd 1
    .security_desc:  resq 1
    .security_qos:   resq 1
endstruc

struc MEMORY_BASIC_INFORMATION
    .base:               resq 1
    .allocation_base:    resq 1
    .allocation_protect: resd 1
    .padding:            resd 1
    .region_size:        resq 1
    .state:              resd 1
    .protect:            resd 1
    .type:               resd 1
    .padding1:           resd 1
endstruc

%if 0
00000000  50                push rax
00000001  48B8371337133713  mov rax,0x1337133713371337
         -3713
0000000B  FFE0              jmp rax
%endif

shellcode:
    struc sc_locals
        .filename:    resb UNICODE_STRING_size
        .info_file:   resq 1
        .memory_file: resq 1
        .meminf:      resb MEMORY_BASIC_INFORMATION_size
    endstruc

%if 0
    ; Get the original rax
    pop rax
%endif

    ; Save all GPR register state
    push rsp
    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    pushfq

    ; Save the address of the register state
    mov r12, rsp

    ; 16-byte align the stack
    and rsp, ~0xf

    ; Allocate room for and save the floating point state
    sub rsp, 512
    mov r13, rsp
    fxsave64 [r13]

    ; Make room for the locals
    sub rsp, sc_locals_size
    mov rbp, rsp

    ; Create the filename for the memory layout and register state
    mov word [rbp + sc_locals.filename + UNICODE_STRING.length], \
        memory_info_len
    mov word [rbp + sc_locals.filename + UNICODE_STRING.max_length], \
        memory_info_len
    lea rax, [rel memory_info]
    mov qword [rbp + sc_locals.filename + UNICODE_STRING.ptr], rax

    ; Create the file
    lea  r10, [rbp + sc_locals.filename]
    call create_file
    mov [rbp + sc_locals.info_file], rax
    
    ; Create the filename for the memory dump
    mov word [rbp + sc_locals.filename + UNICODE_STRING.length],     memory_len
    mov word [rbp + sc_locals.filename + UNICODE_STRING.max_length], memory_len
    lea rax, [rel memory]
    mov qword [rbp + sc_locals.filename + UNICODE_STRING.ptr], rax

    ; Create the file
    lea  r10, [rbp + sc_locals.filename]
    call create_file
    mov [rbp + sc_locals.memory_file], rax
    
    ; Write the register state to the info file
    mov  rcx, [rbp + sc_locals.info_file]
    mov  rdx, r12
    mov  r8,  8 * 17 ; 16 GPRs + flags
    call write_file
    test eax, eax
    jnz  error
    
    ; Write the floating point state to the info file
    mov  rcx, [rbp + sc_locals.info_file]
    mov  rdx, r13
    mov  r8,  512
    call write_file
    test eax, eax
    jnz  error

    ; Base address to scan
    mov r15, 0
.loop:
    ; Make room for the syscalls arguments on the stack
    sub rsp, 0x38

    ; Set up the arguments
    mov r10, -1                       ; ProcessHandle
    mov rdx, r15                      ; BaseAddress
    xor r8d, r8d                      ; MemoryInformationClass
    lea r9,  [rbp + sc_locals.meminf] ; MemoryInformation

    ; MemoryInformationLength
    mov qword [rsp + 0x28], MEMORY_BASIC_INFORMATION_size
    mov qword [rsp + 0x30], 0 ; ReturnLength
    
    ; Invoke NtQueryVirtualMemory()
    mov eax, 0x23
    syscall

    ; Restore the stack from the call
    add rsp, 0x38

    ; Make sure the syscall succeeded
    test eax, eax
    jnz  .done

    ; Update the base of the scan to reflect the size of the region we just
    ; observed
    add r15, [rbp + sc_locals.meminf + MEMORY_BASIC_INFORMATION.region_size]

    ; Attempt to write the memory region, if the kernel cannot read the memory
    ; this will fail and we'll go to the next section
    mov  rcx, [rbp + sc_locals.memory_file]
    mov  rdx, [rbp + sc_locals.meminf + MEMORY_BASIC_INFORMATION.base]
    mov  r8,  [rbp + sc_locals.meminf + MEMORY_BASIC_INFORMATION.region_size]
    call write_file
    test eax, eax
    jnz  .loop

    ; Write the metadata for this saved region
    mov  rcx, [rbp + sc_locals.info_file]
    lea  rdx, [rbp + sc_locals.meminf]
    mov  r8,  MEMORY_BASIC_INFORMATION_size
    call write_file
    test eax, eax
    jnz  error

    ; Go to the next section
    jmp .loop

    add rsp, sc_locals_size

.done:
    ; NtTerminateProcess(GetCurrentProcess(), 0x1234);
    mov r10, -1
    mov edx, 0x1234
    mov eax, 0x2c
    syscall

; Invoked on an error
error:
    ud2

; Create a file if it does not already exist, on error, jumps to `error`
; r10 -> PUNICODE_STRING
; rax <- HANDLE
create_file:
    struc cf_locals
        .handle:  resq 1
        .iosb:    resq 2
        .objattr: resb OBJECT_ATTRIBUTES_size
    endstruc

    ; Save registers
    push rbp
    push rdi

    ; Make room on the stack for the cf_locals
    sub rsp, cf_locals_size
    mov rbp, rsp

    ; Zero initialize all the cf_locals
    cld
    mov rdi, rbp
    xor eax, eax
    mov ecx, cf_locals_size
    rep stosb

    ; Initialize the object attributes
    mov dword [rsp + cf_locals.objattr + OBJECT_ATTRIBUTES.length], \
        OBJECT_ATTRIBUTES_size
    mov qword [rsp + cf_locals.objattr + OBJECT_ATTRIBUTES.object_name], r10

    ; Make room for the arguments on the stack
    sub rsp, 0x60

    ; Set up the arguments
    lea r10, [rbp + cf_locals.handle]  ; FileHandle
    mov edx, 0x120116                  ; DesiredAccess (FILE_GENERIC_WRITE)
    lea  r8, [rbp + cf_locals.objattr] ; ObjectAttributes
    lea  r9, [rbp + cf_locals.iosb]    ; IoStatusBlock
    mov qword [rsp + 0x28], 0          ; AllocationSize
    mov qword [rsp + 0x30], 0x80       ; FileAttributes (FILE_ATTRIBUTE_NORMAL)
    mov qword [rsp + 0x38], 0          ; ShareAccess
    mov qword [rsp + 0x40], 2          ; CreateDisposition (FILE_CREATE)
    mov qword [rsp + 0x48], 0x20       ; CreateOptions
                                       ;     (FILE_SYNCHRONOUS_IO_NONALERT)
    mov qword [rsp + 0x50], 0          ; EaBuffer
    mov qword [rsp + 0x58], 0          ; EaLength

    ; Invoke NtCreateFile
    mov eax, 0x55
    syscall

    ; Jump to error on errors
    test eax, eax
    jnz  error

    ; Return the handle
    mov rax, [rbp + cf_locals.handle]

    ; Free the arguments from the stack as well as the cf_locals
    add rsp, 0x60 + cf_locals_size

    ; Restore registers
    pop rdi
    pop rbp

    ; Return back
    ret

; Write to a file based on the handle in `rcx`
; rcx -> Handle
; rdx -> Buffer
; r8  -> Length
; rax <- NTSTATUS
write_file:
    struc wf_locals
        .iosb: resq 2
    endstruc

    ; Save registers
    push rbp

    ; Allocate local space on the stack
    sub rsp, wf_locals_size
    mov rbp, rsp
    
    ; Save all arguments for partial writes
    push rcx
    push rdx
    push r8

    ; Allocate room for the arguments
    sub rsp, 0x50

    ; Initialize the IOSB
    lea rax, [rbp + wf_locals.iosb]
    mov qword [rax + 0], 0
    mov qword [rax + 8], 0
    
    ; Populate the arguments on the stack
    mov qword [rsp + 0x28], rax ; IoStatusBlock
    mov qword [rsp + 0x30], rdx ; Buffer
    mov qword [rsp + 0x38], r8  ; Length
    mov qword [rsp + 0x40], 0   ; ByteOffset
    mov qword [rsp + 0x48], 0   ; Key
    
    ; Pass the register-based arguments (the first 4)
    mov r10, rcx ; FileHandle
    xor edx, edx ; Event
    xor r8d, r8d ; ApcRoutine
    xor r9d, r9d ; ApcContext

    ; Call NtWriteFile()
    mov eax, 0x08
    syscall
    add rsp, 0x50

    ; Restore parameters
    pop r8
    pop rdx
    pop rcx

    ; Check if we had a failure
    test eax, eax
    jnz  .failure

    ; Write was successful, check for a partial write
    cmp r8, qword [rbp + wf_locals.iosb + 8]
    jne error

.failure:
    add rsp, wf_locals_size
    pop rbp
    ret

align 2
memory_info: dw __utf16__('\??\C:\users\pleb\falkdump.info')
memory_info_len: equ ($ - memory_info)

align 2
memory: dw __utf16__('\??\C:\users\pleb\falkdump.memory')
memory_len: equ ($ - memory)

