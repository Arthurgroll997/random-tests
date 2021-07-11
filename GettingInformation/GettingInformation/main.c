#define _CRT_SECURE_NO_WARNINGS
#include "main.h"

// Just getting some useful information and testing the whole NTAPI and WINAPI world - by Arthur Von Groll

int main()
{
    if (initializeNTFunctions())
    {
        targetProcess = "ac_client.exe";

        HANDLE hProc = openProc(targetProcess);

        if (!hProc)
        {
            ERRO(L"Não foi possível abrir uma handle para o processo alvo.", L"ERRO 0x0002");
            return 0;
        }

        DWORD moduleBaseAddr = getModuleBaseAddrExternal(hProc, targetProcess);
        DWORD moduleSize = getModuleSizeExternal(hProc, targetProcess);
        DWORD patternAddr = (DWORD)(findPattern(hProc, moduleBaseAddr, moduleSize + 1, "\x8B\x44\x24\x2C\x89\x8A\xFC\x00\x00\x00\x89\x82\xF8\x00\x00\x00", "xxxxxxxxxxxxxxxx", 16)) + 10;

        printf("A base de %s e: 0x%08X\n", targetProcess, moduleBaseAddr);
        printf("O tamanho de %s e: 0x%08X\n", targetProcess, moduleSize);
        printf("O endereco do padrao escolhido e: 0x%08X\n", patternAddr);

        CloseHandle(hProc);
    }
    else
    {
        ERRO(L"Não foi possível inicializar as funções da NTAPI.", L"ERRO 0x0001");
    }
    return 0;
}

LPVOID findPattern(HANDLE hProc, DWORD startAddress, DWORD maxSizeToSearch, char* bytes, char* pattern, DWORD size)
{
    DWORD realSize = size ? size : strlen(bytes);
    BOOL patternFound = FALSE;
    BYTE* bytesConverted = (BYTE*)bytes;

    if (startAddress < 0x400000) return NULL; // We want at least the first module in the module list

    BYTE currentByte = 0;
    DWORD actualPosition = 0;
    DWORD addressFound = 0;
    DWORD protectionSize = 1;
    DWORD oldProtection;
    DWORD realAddress;

    for (DWORD i = 0; (!patternFound) && (i < maxSizeToSearch); i++)
    {
        realAddress = startAddress + i;
        if (actualPosition == realSize) patternFound = TRUE;

        ntUtils.ntProtectMemory(hProc, &realAddress, &protectionSize, PAGE_READONLY | PAGE_EXECUTE_READWRITE | PAGE_READWRITE, &oldProtection);
        if (NT_SUCCESS(ntUtils.ntReadMemory(hProc, (BYTE*)(realAddress), &currentByte, 1, NULL)))
        {
            if ((bytesConverted[actualPosition] == currentByte) || (pattern[actualPosition] == '?'))
            {
                if (actualPosition == 0) addressFound = i;
                actualPosition++;
            }
            else if (actualPosition > 0)
            {
                actualPosition = 0;
                i = addressFound;
            }

            ntUtils.ntProtectMemory(hProc, &realAddress, &protectionSize, oldProtection, NULL);
        }
    }

    return patternFound ? realAddress - realSize : NULL;
}

PVOID getExternalInfo(HANDLE hProc, ULONG address, ULONG size)
{
    PVOID baseAddr = calloc(size, sizeof(BYTE)); // I like to use it this way, but feel free to use malloc(size) if you want to.

    if (!NT_SUCCESS(ntUtils.ntReadMemory(hProc, address, baseAddr, size, NULL))) return NULL;

    return baseAddr;
}

DWORD getModuleSize(HANDLE hProc, char* moduleName)
{
    PWCHAR convertedModuleName = (PWCHAR)calloc(strlen(moduleName) + 1, sizeof(WCHAR));
    mbstowcs(convertedModuleName, moduleName, strlen(moduleName));

    PPEB procPeb = getProcessPEB(hProc);
    PLIST_ENTRY moduleList = procPeb->LoaderData->InLoadOrderModuleList.Flink;
    PLDR_MODULE firstModule = (PLDR_MODULE)CONTAINING_RECORD(moduleList, LDR_MODULE, InLoadOrderModuleList);

    PLDR_MODULE nextModule = firstModule;
    BOOL started = TRUE;

    while (((DWORD)moduleList != (DWORD)firstModule) || (started))
    {
        nextModule = (PLDR_MODULE)CONTAINING_RECORD(moduleList, LDR_MODULE, InLoadOrderModuleList);

        if (wcsstr(nextModule->FullDllName.Buffer, convertedModuleName))
        {
            return (DWORD)nextModule->SizeOfImage;
        }

        moduleList = moduleList->Flink;
    }

    return 0;
}

DWORD getModuleSizeExternal(HANDLE hProc, char* moduleName)
{
    PWCHAR convertedModuleName = (PWCHAR)calloc(strlen(moduleName) + 1, sizeof(WCHAR));
    mbstowcs(convertedModuleName, moduleName, strlen(moduleName));

    PPEB peb = getProcessPEB(hProc);
    PPEB internalPeb = getProcessPEB(GetCurrentProcess());

    PPEB_LDR_DATA pebLdrData = GET_EXT_INFO(hProc, GET_REAL_ADDRESS(peb, internalPeb, LoaderData), PPEB_LDR_DATA, sizeof(ULONG));  // We want the offset so that we can read the "real" LoaderData from the target process. After we get the offset, what we do is read 4 bytes from the address (that is offset + the peb addres), so we get the pointer to what we want.
    PPEB_LDR_DATA internalPebLdrData = internalPeb->LoaderData;

    LIST_ENTRY moduleList = GET_EXT_INFO(hProc, GET_REAL_ADDRESS(pebLdrData, internalPebLdrData, InLoadOrderModuleList), LIST_ENTRY, sizeof(LIST_ENTRY));
    PLIST_ENTRY realModuleList = GET_REAL_ADDRESS(pebLdrData, internalPebLdrData, InLoadOrderModuleList);
    PLIST_ENTRY internalModuleList = internalPeb->LoaderData->InLoadOrderModuleList.Flink;

    PLDR_MODULE firstModule = GET_EXT_INFO(hProc, (DWORD)CONTAINING_RECORD(realModuleList, LDR_MODULE, InLoadOrderModuleList), PLDR_MODULE, sizeof(ULONG));
    PLDR_MODULE internalFirstModule = (PLDR_MODULE)CONTAINING_RECORD(internalModuleList, LDR_MODULE, InLoadOrderModuleList);

    DWORD firstModDword = (DWORD)firstModule;
    PLDR_MODULE currentModule = firstModule;
    PLDR_MODULE internalCurrentModule = internalFirstModule;

    do
    {
        UNICODE_STRING name = GET_EXT_INFO(hProc, GET_REAL_ADDRESS(currentModule, internalCurrentModule, FullDllName), UNICODE_STRING, sizeof(UNICODE_STRING));
        UNICODE_STRING internalName = internalCurrentModule->FullDllName;
        name.Buffer = getExternalInfo(hProc, name.Buffer, name.Length + 2);

        if (name.Buffer == NULL) return 0;

        if (wcsstr(name.Buffer, convertedModuleName))
        {
            return (DWORD)GET_EXT_INFO(hProc, GET_REAL_ADDRESS(currentModule, internalCurrentModule, SizeOfImage), PVOID, sizeof(ULONG));
        }

        realModuleList = GET_EXT_INFO(hProc, GET_REAL_ADDRESS(realModuleList, internalModuleList, Flink), PLIST_ENTRY, sizeof(ULONG));
        internalModuleList = internalModuleList->Flink;

        currentModule = GET_EXT_INFO(hProc, (DWORD)CONTAINING_RECORD(realModuleList, LDR_MODULE, InLoadOrderModuleList), PLDR_MODULE, sizeof(ULONG));

    } while (TRUE);

    return 0;
}

DWORD getModuleBaseAddr(HANDLE hProc, char* moduleName)
{
    PWCHAR convertedModuleName = (PWCHAR)calloc(strlen(moduleName) + 1, sizeof(WCHAR));
    mbstowcs(convertedModuleName, moduleName, strlen(moduleName));

    PPEB procPeb = getProcessPEB(hProc);
    PLIST_ENTRY moduleList = procPeb->LoaderData->InLoadOrderModuleList.Flink;
    PLDR_MODULE firstModule = (PLDR_MODULE)CONTAINING_RECORD(moduleList, LDR_MODULE, InLoadOrderModuleList);

    PLDR_MODULE nextModule = firstModule;
    BOOL started = TRUE;

    while (((DWORD)moduleList != (DWORD)firstModule) || (started))
    {
        nextModule = (PLDR_MODULE)CONTAINING_RECORD(moduleList, LDR_MODULE, InLoadOrderModuleList);

        if (wcsstr(nextModule->FullDllName.Buffer, convertedModuleName))
        {
            return (DWORD)nextModule->BaseAddress;
        }

        moduleList = moduleList->Flink;
    }

    return 0;
}

DWORD getModuleBaseAddrExternal(HANDLE hProc, char* moduleName)
{
    PWCHAR convertedModuleName = (PWCHAR)calloc(strlen(moduleName) + 1, sizeof(WCHAR));
    mbstowcs(convertedModuleName, moduleName, strlen(moduleName));

    PPEB peb = getProcessPEB(hProc);
    PPEB internalPeb = getProcessPEB(GetCurrentProcess());

    PPEB_LDR_DATA pebLdrData = GET_EXT_INFO(hProc, GET_REAL_ADDRESS(peb, internalPeb, LoaderData), PPEB_LDR_DATA, sizeof(ULONG));  // We want the offset so that we can read the "real" LoaderData from the target process. After we get the offset, what we do is read 4 bytes from the address (that is offset + the peb addres), so we get the pointer to what we want.
    PPEB_LDR_DATA internalPebLdrData = internalPeb->LoaderData;
    
    LIST_ENTRY moduleList = GET_EXT_INFO(hProc, GET_REAL_ADDRESS(pebLdrData, internalPebLdrData, InLoadOrderModuleList), LIST_ENTRY, sizeof(LIST_ENTRY));
    PLIST_ENTRY realModuleList = GET_REAL_ADDRESS(pebLdrData, internalPebLdrData, InLoadOrderModuleList);
    PLIST_ENTRY internalModuleList = internalPeb->LoaderData->InLoadOrderModuleList.Flink;

    PLDR_MODULE firstModule = GET_EXT_INFO(hProc, (DWORD)CONTAINING_RECORD(realModuleList, LDR_MODULE, InLoadOrderModuleList), PLDR_MODULE, sizeof(ULONG));
    PLDR_MODULE internalFirstModule = (PLDR_MODULE)CONTAINING_RECORD(internalModuleList, LDR_MODULE, InLoadOrderModuleList);

    DWORD firstModDword = (DWORD)firstModule;
    PLDR_MODULE currentModule = firstModule;
    PLDR_MODULE internalCurrentModule = internalFirstModule;

    do
    {
        UNICODE_STRING name = GET_EXT_INFO(hProc, GET_REAL_ADDRESS(currentModule, internalCurrentModule, FullDllName), UNICODE_STRING, sizeof(UNICODE_STRING));
        UNICODE_STRING internalName = internalCurrentModule->FullDllName;
        name.Buffer = getExternalInfo(hProc, name.Buffer, name.Length + 2);

        if (name.Buffer == NULL) return 0;

        if (wcsstr(name.Buffer, convertedModuleName))
        {
            return (DWORD)GET_EXT_INFO(hProc, GET_REAL_ADDRESS(currentModule, internalCurrentModule, BaseAddress), PVOID, sizeof(ULONG));
        }

        realModuleList = GET_EXT_INFO(hProc, GET_REAL_ADDRESS(realModuleList, internalModuleList, Flink), PLIST_ENTRY, sizeof(ULONG));
        internalModuleList = internalModuleList->Flink;

        currentModule = GET_EXT_INFO(hProc, (DWORD)CONTAINING_RECORD(realModuleList, LDR_MODULE, InLoadOrderModuleList), PLDR_MODULE, sizeof(ULONG));

    } while (TRUE);

    return 0;
}

PPEB getProcessPEB(HANDLE hProc)
{
    PROCESS_BASIC_INFORMATION procBasicInfo;
    ULONG correctLen;
    if (!NT_SUCCESS(ntUtils.ntQueryProcess(hProc, ProcessBasicInformation, &procBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &correctLen))) return NULL;

    return procBasicInfo.PebBaseAddress;
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
        if (((DWORD)procInfo == NULL) || (procInfo->NextEntryOffset == 0)) return 0;

        if (procInfo->ImageName.Length == 0)
        {
            continue;
        }

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