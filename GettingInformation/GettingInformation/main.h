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
DWORD getProcId(char* procName);
int main();
BOOL initializeNTFunctions();