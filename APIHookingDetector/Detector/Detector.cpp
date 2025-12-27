#include <stdio.h>
#include <windows.h>
#include <winternl.h>

BOOL DetectHook(LPVOID hookedfuncaddr) {
    BYTE realbytes[] = "\x4C\x8B\xD1\xB8";
    if (memcmp(realbytes, hookedfuncaddr, 4) == 0) {
        return true;
    }
    else {
        return false;
    }
}

void Banner() {
    printf(R"EOF(

      _____ __________.___    ___ ___                __   .__                 ________          __                 __                
  /  _  \\______   \   |  /   |   \  ____   ____ |  | _|__| ____    ____   \______ \   _____/  |_  ____   _____/  |_  ___________ 
 /  /_\  \|     ___/   | /    ~    \/  _ \ /  _ \|  |/ /  |/    \  / ___\   |    |  \_/ __ \   __\/ __ \_/ ___\   __\/  _ \_  __ \
/    |    \    |   |   | \    Y    (  <_> |  <_> )    <|  |   |  \/ /_/  >  |    `   \  ___/|  | \  ___/\  \___|  | (  <_> )  | \/
\____|__  /____|   |___|  \___|_  / \____/ \____/|__|_ \__|___|  /\___  /  /_______  /\___  >__|  \___  >\___  >__|  \____/|__|   
        \/                      \/                    \/       \//_____/           \/     \/          \/     \/                                    
                                  
                                    [ Developed By @ftz7]
                                         [v1.0]

)EOF");
}

void Help(char* progname) {
    printf(R"EOF(usage: %s OUTPUT
    options:
      OUTPUT,                   output file
)EOF", progname);
}

int main(int argc, char* argv[]) {
    bool hasHook = false;

    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (ntdll == NULL) {
        printf("[-] Error loading ntdll.dll\n");
        return 1;
    }

    if (argv[1] == NULL) {
        Banner();
        Help(argv[0]);
        return 1;
    }

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((char*)dos_header + dos_header->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((char*)ntdll + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* function_names = (DWORD*)((char*)ntdll + exports->AddressOfNames);

    int outputfname = strlen(argv[1]) + 1;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, argv[1], outputfname, NULL, 0);
    wchar_t* wdmpout = (wchar_t*)malloc(wlen * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, argv[1], outputfname, wdmpout, wlen);
    HANDLE outputf = CreateFileW(wdmpout, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    char breakline[] = "\n";

    Banner();
    puts("[*] NT API being hooked:");
    puts("=========================================================================================");
    for (int i = 0; i < exports->NumberOfFunctions; i++) {
        char* ntFunction = (char*)ntdll + function_names[i];
        //printf("%s\n", ntFunction);
        if (strncmp(ntFunction, "Nt", 2) == 0) {
            if (strncmp(ntFunction, "NtdllDialogWndProc", 18) != 0 && strncmp(ntFunction, "NtdllDefWindowProc", 18) != 0) {       // blacklist nt funcs
                FARPROC procaddr = GetProcAddress(ntdll, (LPCSTR)ntFunction);
                if (procaddr == NULL) {
                    printf("[-] Error finding function %s\n", ntFunction);
                    return 1;
                }
                LPBYTE lpprocaddr = (LPBYTE)procaddr;
                DWORD dwprocaddr = *(DWORD*)lpprocaddr;
                char realbytes[] = "0xB8D18B4C";
                DWORD Written;

                if (strncmp(ntFunction, "NtQuerySystemTime", 17) == 0 && memcmp("\xE9\x4B", procaddr, 2) != 0) {
                    hasHook = true;
                    printf("[-] %s [%s != 0x%02X]\n", ntFunction, "0x****4BE9", dwprocaddr);
                    WriteFile(outputf, ntFunction, strlen(ntFunction), &Written, NULL);
                    WriteFile(outputf, breakline, strlen(breakline), &Written, NULL);
                }
                else if (strncmp(ntFunction, "NtGetTickCount", 14) == 0 && memcmp("\xB9\x20", procaddr, 2) != 0) {
                    hasHook = true;
                    printf("[-] %s [%s != 0x%02X]\n", ntFunction, "0x****20B9", dwprocaddr);
                    WriteFile(outputf, ntFunction, strlen(ntFunction), &Written, NULL);
                    WriteFile(outputf, breakline, strlen(breakline), &Written, NULL);
                }
                else if (strncmp(ntFunction, "NtQuerySystemTime", 17) != 0 && strncmp(ntFunction, "NtGetTickCount", 14) != 0 && !DetectHook(procaddr)) {
                    hasHook = true;
                    printf("[-] %s [%s != 0x%02X]\n", ntFunction, realbytes, dwprocaddr);
                    WriteFile(outputf, ntFunction, strlen(ntFunction), &Written, NULL);
                    WriteFile(outputf, breakline, strlen(breakline), &Written, NULL);
                }
            }
        }
    }

    if (!hasHook) {
        puts("[+] You are safe, there is no hook in the NT API");
    }

    puts("=========================================================================================");

    CloseHandle(outputf);
    FreeLibrary(ntdll);
    return 0;
}
