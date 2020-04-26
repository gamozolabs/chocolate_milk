#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <windows.h>
#include <winternl.h>

int
main(int argc, char *argv[])
{
    if(argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <address to snapshot upon exec>\n",
                argc ? argv[0] : "program.exe");
        return 1;
    }

    DWORD pid = strtoul(argv[1], NULL, 0);
    uintptr_t snapshot_addr = strtoul(argv[2], NULL, 0);
    if(pid == 0 || snapshot_addr == 0) {
        fprintf(stderr, "Invalid digit in pid or snapshot address\n");
        return 1;
    }

    void *shellcode = calloc(1, 32 * 1024);
    if (!shellcode) {
        perror("calloc() error ");
        return -1;
    }

    FILE *fd = fopen("shellcode.bin", "rb");
    if (!fd) {
        perror("fopen() error ");
        return -1;
    }

    intptr_t bread = fread(shellcode, 1, 32 * 1024, fd);
    fclose(fd);
    if (bread <= 0) {
        perror("fread() error ");
        return -1;
    }

    printf("Shellcode is %zd bytes\n", bread);

    HANDLE proc = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            FALSE, pid);
    if(!proc) {
        fprintf(stderr, "OpenProcess() error : %d\n", GetLastError());
        return -1;
    }

    void *addr = VirtualAllocEx(
            proc, NULL, bread, MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
    if(!addr) {
        fprintf(stderr, "VirtualAllocEx() error : %d\n", GetLastError());
        return -1;
    }

    size_t bwritten = 0;
    if(!WriteProcessMemory(proc, addr, shellcode,
                bread, &bwritten) || bwritten != bread) {
        fprintf(stderr, "WriteProcessMemory() error : %d\n", GetLastError());
        return -1;
    }

    // Create the jump to shellcode pad
    // push rax
    // mov rax, imm64
    // jmp rax
    char inject[] = { 0x50, 0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xe0 };
    *(uintptr_t*)(inject + 3) = (uintptr_t)addr;

    bwritten = 0;
    if(!WriteProcessMemory(proc, snapshot_addr, inject,
                sizeof(inject), &bwritten) || bwritten != sizeof(inject)) {
        fprintf(stderr, "WriteProcessMemory(IJ) error : %d\n", GetLastError());
        return -1;
    }

    printf("Injected!\n");

    return 0;
}

