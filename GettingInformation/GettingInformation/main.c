#define _CRT_SECURE_NO_WARNINGS
#include "main.h"

// Just getting some useful information and testing the whole NTAPI and WINAPI world - by Arthur Von Groll

int main()
{
    if (initializeNTFunctions())
    {
        targetProcess = "ac_client.exe";

        DWORD targetProcId = getProcId(targetProcess);
        BOOL isX86;

        isProcessX86(targetProcess, &isX86);

        HANDLE hProc = openProc(targetProcess);

        if (!hProc)
        {
            ERRO(L"Não foi possível abrir uma handle para o processo alvo.", L"ERRO 0x0002");
            return 0;
        }

        CloseHandle(hProc);
    }
    else
    {
        ERRO(L"Não foi possível inicializar as funções da NTAPI.", L"ERRO 0x0001");
    }
    return 0;
}

HANDLE openProc(char* procName)
{
    HANDLE hProc;
    POBJECT_ATTRIBUTES oa = (POBJECT_ATTRIBUTES)calloc(1, sizeof(OBJECT_ATTRIBUTES));
    oa->Length = sizeof(OBJECT_ATTRIBUTES);

    PCLIENT_ID cid = (PCLIENT_ID)calloc(1, sizeof(CLIENT_ID));
    cid->UniqueProcess = getProcId(procName);

    ntUtils.ntOpenProcess(&hProc, PROCESS_ALL_ACCESS, oa, cid);

    return hProc;
}

DWORD getProcId(char* procName)
{
    PSYSTEM_PROCESS_INFORMATION procInfo = (PSYSTEM_PROCESS_INFORMATION)calloc(1024 * 1024, sizeof(BYTE));

    if (!NT_SUCCESS(ntUtils.ntQuerySystemInfo(SystemProcessInformation, procInfo, 1024 * 1024, NULL))) return 0;

    PWCHAR procNameConverted = (PWCHAR)calloc(strlen(procName) + 1, sizeof(WCHAR));
    mbstowcs(procNameConverted, procName, strlen(procName));

    for (; procInfo; procInfo = (PSYSTEM_PROCESS_INFORMATION)((DWORD)procInfo + (DWORD)procInfo->NextEntryOffset))
    {
        if (procInfo->ImageName.Length == 0) continue;
        if (!wcscmp(procInfo->ImageName.Buffer, procNameConverted))
        {
            return procInfo->ProcessId;
        }
    }

    return 0;
}

BOOL isProcessX86(char* procName, PBOOL returnValue)
{
    ULONG isX64;
    ULONG bugzin;
    HANDLE procHandle = openProc(procName);

    if (!procHandle) return FALSE;
    if (!NT_SUCCESS(ntUtils.ntQueryProcess(procHandle, 26, &isX64, sizeof(ULONG), &bugzin))) return FALSE; /* 26 stands for: ProcessWow64Information - MSDN page: https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess */

    *returnValue = isX64 != 0;
    return TRUE;
}

BOOL initializeNTFunctions()
{
#if X86
    ntUtils.ntDllLocation = 0x7FF991EE;
#elif X64
    ntUtils.ntDllLocation = 0x7FF991EE0000;
#endif
    /* Getting all the functions addresses that we want */
    ntUtils.ntReadMemory = (NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
    ntUtils.ntWriteMemory = (NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    ntUtils.ntProtectMemory = (NtProtectVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    ntUtils.ntQueryMemory = (NtQueryVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryVirtualMemory");
    ntUtils.ntFreeMemory = (NtFreeVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFreeVirtualMemory");
    ntUtils.ntAllocMemory = (NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    ntUtils.ntQueryProcess = (NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    ntUtils.ntSetProcessInfo = (NtSetInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
    ntUtils.ntOpenProcess = (NtOpenProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess");
    ntUtils.ntGetProcAddress = (LdrGetProcedureAddress)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrGetProcedureAddress");
    ntUtils.ntGetDllHandle = (LdrGetDllHandle)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrGetDllHandle");
    ntUtils.ntInitUnicodeString = (RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
    ntUtils.ntQuerySystemInfo = (NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    ntUtils.ntQueryProcModuleInfo = (LdrQueryProcessModuleInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrQueryProcessModuleInformation");
    
    DWORD baseAddr = (DWORD)&ntUtils;

    /* Checking if we actually obtained all the addresses successfully */
    for (int i = 0; i < sizeof(ntUtils) / 4; i++)
    {
        if (*(DWORD*)(baseAddr + (i * 4)) == NULL)
        {
            return FALSE;
        }
    }

    return TRUE;
}