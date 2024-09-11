#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void NXOR(char *shellcode, char *clave, char *shellcode_cifrada) {
    for (int i = 0; i < strlen(shellcode); i++) {
        shellcode_cifrada[i] = ~(shellcode[i] ^ clave[i % strlen(clave)]);
    }
}

int main() {
    char shellcode_b64[] = "base64 shellcode";
    char clave[] = "NX0R-D3F3ND3R";

    int shellcode_longitud = strlen(shellcode_b64);
    char *shellcode_cifrada = (char *)malloc(shellcode_longitud + 1);

    NXOR(shellcode_b64, clave, shellcode_cifrada);
    
    for (int i = 0; i < shellcode_longitud; i++) {
        printf("%02X", (unsigned char)shellcode_cifrada[i]);
    }

    printf("\n");
    free(shellcode_cifrada);

    return 0;
}
