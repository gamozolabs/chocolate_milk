[bits 32]

struc register_state
	.eax: resd 1
	.ecx: resd 1
	.edx: resd 1
	.ebx: resd 1
	.esp: resd 1
	.ebp: resd 1
	.esi: resd 1
	.edi: resd 1
	.efl: resd 1

	.es: resw 1
	.ds: resw 1
	.fs: resw 1
	.gs: resw 1
	.ss: resw 1
endstruc

section .text

global _invoke_realmode
_invoke_realmode:
	pushad

	; Set all selectors to data segments
	mov ax, 0x10
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov ss, ax
	jmp 0x0008:(.foop - PROGRAM_BASE)

[bits 16]
.foop:
	; Disable protected mode
	mov eax, cr0
	and eax, ~1
	mov cr0, eax

	; Clear out all segments
	xor ax, ax
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov ss, ax

	; Set up a fake iret to do a long jump to switch to new cs.
	pushfd                                ; eflags
	push dword (PROGRAM_BASE >> 4)        ; cs
	push dword (.new_func - PROGRAM_BASE) ; eip
	iretd

.new_func:
	; Get the arguments passed to this function
	movzx ebx, byte  [esp + (4*0x9)] ; arg1, interrupt number
	shl   ebx, 2
	mov   eax, dword [esp + (4*0xa)] ; arg2, pointer to registers

	; Set up interrupt stack frame. This is what the real mode routine will
	; pop off the stack during its iret.
	mov ebp, (.retpoint - PROGRAM_BASE)
	pushfw
	push cs
	push bp

	; Set up the call for the interrupt by loading the contents of the IVT
	; based on the interrupt number specified
	pushfw
	push word [bx+2]
	push word [bx+0]

	; Load the register state specified
	mov ecx, dword [eax + register_state.ecx]
	mov edx, dword [eax + register_state.edx]
	mov ebx, dword [eax + register_state.ebx]
	mov ebp, dword [eax + register_state.ebp]
	mov esi, dword [eax + register_state.esi]
	mov edi, dword [eax + register_state.edi]
	mov eax, dword [eax + register_state.eax]

	; Perform a long jump to the interrupt entry point, simulating a software
	; interrupt instruction
	iretw
.retpoint:
	; Save off all registers
	push eax
	push ecx
	push edx
	push ebx
	push ebp
	push esi
	push edi
	pushfd
	push es
	push ds
	push fs
	push gs
	push ss

	; Get a pointer to the registers
	mov eax, dword [esp + (4*0xa) + (4*8) + (5*2)] ; arg2, pointer to registers

	; Update the register state with the post-interrupt register state.
	pop  word [eax + register_state.ss]
	pop  word [eax + register_state.gs]
	pop  word [eax + register_state.fs]
	pop  word [eax + register_state.ds]
	pop  word [eax + register_state.es]
	pop dword [eax + register_state.efl]
	pop dword [eax + register_state.edi]
	pop dword [eax + register_state.esi]
	pop dword [eax + register_state.ebp]
	pop dword [eax + register_state.ebx]
	pop dword [eax + register_state.edx]
	pop dword [eax + register_state.ecx]
	pop dword [eax + register_state.eax]

	; Enable protected mode
	mov eax, cr0
	or  eax, 1
	mov cr0, eax

	; Set all segments to data segments
	mov ax, 0x20
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov ss, ax

	; Long jump back to protected mode.
	pushfd             ; eflags
	push dword 0x0018  ; cs
	push dword backout ; eip
	iretd

[bits 32]

global _pxecall
_pxecall:
	pushad

	; Set all selectors to data segments
	mov ax, 0x10
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov ss, ax

	jmp 0x0008:(.foop - PROGRAM_BASE)

[bits 16]
.foop:
	; Disable protected mode
	mov eax, cr0
	and eax, ~1
	mov cr0, eax

	; Clear all segments
	xor ax, ax
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov ss, ax

	; Perform a long jump to real-mode
	pushfd                                ; eflags
	push dword (PROGRAM_BASE >> 4)        ; cs
	push dword (.new_func - PROGRAM_BASE) ; eip
	iretd

.new_func:

	;    pub fn pxecall(seg: u16, off: u16, pxe_call: u16,
	;                   param_seg: u16, param_off: u16);
	movzx eax, word [esp + (4*0x9)] ; arg1, seg
	movzx ebx, word [esp + (4*0xa)] ; arg2, offset
	movzx ecx, word [esp + (4*0xb)] ; arg3, pxe_call
	movzx edx, word [esp + (4*0xc)] ; arg4, param_seg
	movzx esi, word [esp + (4*0xd)] ; arg5, param_off

	; Set up PXE call parameters (opcode, offset, seg)
	push dx
	push si
	push cx

	; Set up our return address from the far call
	mov ebp, (.retpoint - PROGRAM_BASE)
	push cs
	push bp

	; Set up a far call via iretw
	pushfw
	push ax
	push bx

	iretw
.retpoint:
	; Hyper-V has been observed to set the interrupt flag in PXE routines. We
	; clear it ASAP.
	cli

	; Clean up the stack from the 3 word parameters we passed to PXE
	add sp, 6

	; Enable protected mode
	mov eax, cr0
	or  eax, 1
	mov cr0, eax

	; Set all segments to data segments
	mov ax, 0x20
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov ss, ax

	; Jump back to protected mode
	pushfd             ; eflags
	push dword 0x0018  ; cs
	push dword backout ; eip
	iretd

[bits 32]
backout:
	popad
	ret

global _enter64
_enter64:
	; qword [esp + 0x04] - Entry
	; qword [esp + 0x0c] - Stack
	; qword [esp + 0x14] - Param
	; dword [esp + 0x1c] - Kernel cr3
	; dword [esp + 0x20] - Trampoline cr3
    ; qword [esp + 0x24] - Physical window address

	; Get the parameters passed in to this function
	mov esi, [esp+0x20] ; Trampoline cr3
	mov ebx, [esp+0x1c] ; Kernel cr3

	; Set up CR3
	mov cr3, esi

	; Set NXE (NX enable) and LME (long mode enable)
	mov edx, 0
	mov eax, 0x00000900
	mov ecx, 0xc0000080
	wrmsr

	xor eax, eax
	or  eax, (1 <<  9) ; OSFXSR
	or  eax, (1 << 10) ; OSXMMEXCPT
	or  eax, (1 <<  5) ; PAE
	or  eax, (1 <<  3) ; DE
	mov cr4, eax

	xor eax, eax
	or  eax,  (1 <<  0) ; Protected mode enable
    or  eax,  (1 <<  1) ; Monitor co-processor
	and eax, ~(1 <<  2) ; Clear Emulation flag
	or  eax,  (1 << 16) ; Write protect
	or  eax,  (1 << 31) ; Paging enable
	mov cr0, eax

	; Long jump to enable long mode!
	jmp 0x0028:lm_entry

[bits 64]

lm_entry:
	; Set all selectors to 64-bit data segments
	mov ax, 0x30
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov ss, ax
	
    ; Set up a long jump to switch from the identity memory map, to the linear
    ; physical memory map
    mov rax, qword [rsp + 0x24] ; Physical window address
    add rax, .addr
    jmp rax
   
.addr:
	mov rcx, qword [rsp + 0x14] ; Parameter
	mov rdi, qword [rsp + 0x04] ; Entry point
	mov rsp, qword [rsp + 0x0c] ; Stack

    ; At this point the stack and RIP both point to the linear physical map
    ; rather than the identity physical map, so we can now safely switch to
    ; the kernel cr3
    mov cr3, rbx

	sub rsp, 0x28 ; MSFT 64-bit calling convention requires 0x20 homing space
                  ; We also need 8 bytes for the fake 'return address' since we
                  ; iretq rather than call.
    
    ; Jump into the kernel entry
    jmp rdi

