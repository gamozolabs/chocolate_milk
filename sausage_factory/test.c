#pragma warning(push)
#pragma warning(disable:4255)
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <windows.h>
#include <winternl.h>
#include <inttypes.h>
#pragma warning(pop)

#define TEST_ON_SELF

#ifdef TEST_ON_SELF
static void
hook_me(uint8_t *buf, size_t len) {
    if(len != 5) return;

    if(buf[0] == 'h') {
        if(buf[1] == 'e') {
            if(buf[2] == 'l') {
                if(buf[3] == 'l') {
                    if(buf[4] == 'o') {
                        *(volatile char*)(0x123344528) = 0;
                    }
                }
            }
        }
    }

    return;
}
#endif

int
main(int argc, char *argv[])
{
#ifndef TEST_ON_SELF
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
#else
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    DWORD pid = GetCurrentProcessId();
    uintptr_t snapshot_addr = (uintptr_t)hook_me;
#endif

    // Disable buffering on stdout and stderr
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    void *shellcode = calloc(1, 32 * 1024);
    if (!shellcode) {
        perror("calloc() error ");
        return -1;
    }

    FILE *fd;
    errno_t err = fopen_s(&fd, "shellcode.bin", "rb");
    if (err != 0) {
        perror("fopen() error ");
        return -1;
    }

    intptr_t bread = fread(shellcode, 1, 32 * 1024, fd);
    fclose(fd);
    if (bread <= 0) {
        perror("fread() error ");
        return -1;
    }

    printf("Shellcode is %Id bytes\n", bread);

    HANDLE proc = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            FALSE, pid);
    if(!proc) {
        fprintf(stderr, "OpenProcess() error : %lu\n", GetLastError());
        return -1;
    }

    void *addr = VirtualAllocEx(
            proc, NULL, bread, MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
    if(!addr) {
        fprintf(stderr, "VirtualAllocEx() error : %lu\n", GetLastError());
        return -1;
    }

    size_t bwritten = 0;
    if(!WriteProcessMemory(proc, addr, shellcode,
                bread, &bwritten) || bwritten != (size_t)bread) {
        fprintf(stderr, "WriteProcessMemory() error : %lu\n", GetLastError());
        return -1;
    }

    // Create the jump to shellcode pad
    // push rax
    // mov rax, imm64
    // jmp rax
    char inject[] = { 0x50, 0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xe0 };
    *(uintptr_t*)(inject + 3) = (uintptr_t)addr;

    bwritten = 0;
    if(!WriteProcessMemory(proc, (void*)snapshot_addr, inject,
                sizeof(inject), &bwritten) || bwritten != sizeof(inject)) {
        fprintf(stderr, "WriteProcessMemory(IJ) error : %lu\n",
                GetLastError());
        return -1;
    }

    printf("Injected to %p!\n", (void*)snapshot_addr);

#ifdef TEST_ON_SELF
    uint8_t *buf = malloc(128);
    hook_me(buf, 128);
#endif

    return 0;
}

