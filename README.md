## ShinJect

ShinJect es un "shellcode injector" que tiene las siguientes caracteristicas:

- Evade windows defender en disco y tiempo de ejecucion (probado en Win10)
- Utiliza la tenica Remote Thread Injection o CreateRemoteThread
- La shellcode se encuentra codificada en b64 y posteriormente cifrada en NXOR de clave repetida
- Resuelve en tiempo de ejecucion las funciones de la WinAPI que se usaran en la inyeccion
- Implementa delays en la ejecucion del programa (la shellcode se ejecuta despues de 20 segundos)
- La shellcode se crea en un hilo suspendido el cual se reanuda despues de un delay

### Uso

`La shellcode que trae por defecto ejecuta cmd.exe`

1. Genera una shellcode codificada en base64, como por ejemplo: `msfvenom -p windows/x64/exec CMD="cmd.exe" -f base64`
2. Cifra la shellcode usando NXOR usando el binario que se encuentra en el directorio `modules` (edita el archivo `nxor.c` y pon la shellcode obtenida en el paso anterior)
3. Modifica la shellcode de la variable "shellcode_cifrada" del archivo `shinject.c` del directorio `src`
4. Compila el codigo usando: `x86_64-w64-mingw32-g++ -s -o shinject shinject.c -lcrypt32`
