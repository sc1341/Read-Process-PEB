#include <Windows.h>
#include <TlHelp32.h>
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

void DumpProcessArguments(DWORD pid, pfnNtQueryInformationProcess NtQueryInformationProcess) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        // Skip processes we cannot access
        return;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (!NT_SUCCESS(status)) {
        CloseHandle(hProcess);
        return;
    }

    PEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        CloseHandle(hProcess);
        return;
    }

    RTL_USER_PROCESS_PARAMETERS params;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), NULL)) {
        CloseHandle(hProcess);
        return;
    }

    WCHAR imagePath[MAX_PATH] = { 0 };
    WCHAR commandLine[MAX_PATH] = { 0 };
    if (ReadRemoteUnicodeString(hProcess, &params.ImagePathName, imagePath, sizeof(imagePath)) &&
        ReadRemoteUnicodeString(hProcess, &params.CommandLine, commandLine, sizeof(commandLine))) {
        wprintf(L"PID: %lu\n", pid);
        wprintf(L"Image Path: %s\n", imagePath);
        wprintf(L"Command Line: %s\n\n", commandLine);
    }

    CloseHandle(hProcess);
}

int main() {
    // Dynamically load NtQueryInformationProcess from ntdll.dll
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL) {
        printf("Failed to get a handle on ntdll.dll\n");
        return 1;
    }

    pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) {
        printf("Failed to get NtQueryInformationProcess address\n");
        return 1;
    }

    // Enumerate all processes using CreateToolhelp32Snapshot
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create process snapshot\n");
        return 1;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            DumpProcessArguments(pe32.th32ProcessID, NtQueryInformationProcess);
        } while (Process32Next(hSnapshot, &pe32));
    } else {
        printf("Failed to enumerate processes\n");
    }

    CloseHandle(hSnapshot);
    return 0;
}
