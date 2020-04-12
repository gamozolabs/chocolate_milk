[org  0x7c00]
[bits 16]

entry:
    ; Disable interrupts and clear direction flag
    cli
    cld

	; Set the A20 line
	in    al, 0x92
	or    al, 2
	out 0x92, al

    ; Clear DS
    xor ax, ax
    mov ds, ax

    ; Load a 32-bit GDT
    lgdt [ds:pm_gdt]

    ; Enable protected mode
	mov eax, cr0
	or  eax, (1 << 0)
	mov cr0, eax
    
    ; Transition to 32-bit mode by setting CS to a protected mode selector
    jmp 0x0008:pm_entry

[bits 32]

pm_entry:
    ; Set up all data selectors
    mov ax, 0x10
    mov es, ax
    mov ds, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; Wait for the shared early boot stack to be available for use
.wait_for_stack:
    pause
    xor  al, al
    lock xchg byte [stack_avail], al
    test al, al
    jz   .wait_for_stack

    ; Set up a basic stack
    mov esp, 0x7c00

    ; Jump into Rust! (entry_point is a defined variable during build)
    call entry_point

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

; 32-bit protected mode GDT

align 8
pm_gdt_base:
	dq 0x0000000000000000
	dq 0x00CF9A000000FFFF
	dq 0x00CF92000000FFFF

pm_gdt:
	dw (pm_gdt - pm_gdt_base) - 1
	dd pm_gdt_base

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

times 510-($-$$) db 0
dw 0xaa55

; Do not move this, it must stay at 0x7e00. We release the early boot stack
; once we get into the kernel and are using a new stack. We write directly to
; this location.
stack_avail: db 1

times (0x8000 - 0x7c00)-($-$$) db 0

[bits 16]

ap_entry:
    jmp 0x0000:entry

times (0x8100 - 0x7c00)-($-$$) db 0
incbin "build/chocolate_milk.flat"

