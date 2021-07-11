#pragma once
#include <stdio.h>
#include "myntapi.h"

/* Preprocessors definitions */

#define DEBUG TRUE

#define GET_REAL_ADDRESS(address, structure, field) (DWORD)address + ((DWORD)(&structure->field) - (DWORD)(structure))
#define GET_EXT_INFO(handle, address, type, size) *(type*)getExternalInfo(handle, address, size);

/* Structs and global vars definitions */

struct {
	DWORD ntDllLocation;
	NtReadVirtualMemory ntReadMemory;
	NtWriteVirtualMemory ntWriteMemory;
	NtProtectVirtualMemory ntProtectMemory;
	NtQueryVirtualMemory ntQueryMemory;
	NtFreeVirtualMemory ntFreeMemory;
	NtAllocateVirtualMemory ntAllocMemory;
	NtQueryInformationProcess ntQueryProcess;
	NtSetInformationProcess ntSetProcessInfo;
	NtOpenProcess ntOpenProcess;
	LdrGetProcedureAddress ntGetProcAddress;
	LdrGetDllHandle ntGetDllHandle;
	RtlInitUnicodeString ntInitUnicodeString;
	NtQuerySystemInformation ntQuerySystemInfo;
	LdrQueryProcessModuleInformation ntQueryProcModuleInfo;
} ntUtils;

char* targetProcess;

/* Functions definitions */

HANDLE openProc(char* procName);
BOOL isProcessX86(char* procName, PBOOL returnValue); // Actually, I'll return whether the function worked or not and the actual return value (if the process is x86) will be set in the returnValue parameter.
DWORD getModuleBaseAddr(HANDLE hProc, char* moduleName); // Has to be used internally.
DWORD getModuleSize(HANDLE hProc, char* moduleName); // Has to be used internally.
DWORD getModuleSizeExternal(HANDLE hProc, char* moduleName); // Used externally (or internally if GetCurrentProcess() is passed in hProc).
DWORD getModuleBaseAddrExternal(HANDLE hProc, char* moduleName); // I can't remember the last time I messed up so hard with PEB, this experience was awesome! (Btw, I've never accessed the PEB of processes outside of kernel-mode, so this was indeed a pain in the ass [as I'm dumb enough to don't google examples and try to discover things by myself], but it was good anyways)
PPEB getProcessPEB(HANDLE hProc);
PVOID getExternalInfo(HANDLE hProc, ULONG address, ULONG size); // I'll use it whenever I have to get, for example, the loader data of another process, since I'll get the address relative to the target process. The return value will be the address where the information is stored.
DWORD getProcId(char* procName);
BOOL initializeNTFunctions();
LPVOID findPattern(HANDLE hProc, DWORD startAddress, DWORD maxSizeToSearch, char* bytes, char* pattern, DWORD size); // We will use "x" when the byte is necessary and imutable, and "?" when the byte is useless. The address returned will be the address of the first byte in the pattern, even if it is useless (marked with a "?").
int main();