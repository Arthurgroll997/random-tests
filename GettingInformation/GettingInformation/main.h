#pragma once
#include "myntapi.h"

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
DWORD getProcId(char* procName);
int main();
BOOL initializeNTFunctions();