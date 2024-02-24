#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

// Define the prototype of NtQueryInformationProcess as it's not available in the standard headers
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

BOOL ReadRemoteUnicodeString(HANDLE hProcess, UNICODE_STRING* source, WCHAR* dest, SIZE_T destSize) {
    if (source->Length + sizeof(WCHAR) > destSize) {
        return FALSE; // Ensure buffer is big enough for the string and null terminator
    }

    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, source->Buffer, dest, source->Length, &bytesRead)) {
        return FALSE; // Failed to read memory
    }

    dest[source->Length / sizeof(WCHAR)] = L'\0'; // Null terminate the string
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        printf("Failed to open process with PID %d\n", pid);
        return 1;
    }

    // Dynamically load NtQueryInformationProcess from ntdll.dll
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL) {
        printf("Failed to get a handle on ntdll.dll\n");
        CloseHandle(hProcess);
        return 1;
    }

    pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) {
        printf("Failed to get NtQueryInformationProcess address\n");
        FreeLibrary(hNtdll);
        CloseHandle(hProcess);
        return 1;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (!NT_SUCCESS(status)) {
        printf("NtQueryInformationProcess failed\n");
        FreeLibrary(hNtdll);
        CloseHandle(hProcess);
        return 1;
    }

    PEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        printf("Failed to read PEB\n");
        FreeLibrary(hNtdll);
        CloseHandle(hProcess);
        return 1;
    }

    RTL_USER_PROCESS_PARAMETERS params;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), NULL)) {
        printf("Failed to read process parameters\n");
        FreeLibrary(hNtdll);
        CloseHandle(hProcess);
        return 1;
    }

    WCHAR imagePath[MAX_PATH] = { 0 };
    WCHAR commandLine[MAX_PATH] = { 0 };
    if (ReadRemoteUnicodeString(hProcess, &params.ImagePathName, imagePath, sizeof(imagePath)) &&
        ReadRemoteUnicodeString(hProcess, &params.CommandLine, commandLine, sizeof(commandLine))) {
        wprintf(L"Image Path: %s\n", imagePath);
        wprintf(L"Command Line: %s\n", commandLine);
    }
    else {
        printf("Failed to read string from process\n");
    }

    FreeLibrary(hNtdll);
    CloseHandle(hProcess);
    return 0;
}
