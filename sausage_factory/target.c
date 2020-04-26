#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <windows.h>
#include <winternl.h>

int
main(int argc, char *argv[]) {
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
}

