#pragma once
#include "structs.h"

namespace memory {
    PVOID GetSystemModuleBase(const char* module_name);
    PVOID GetSystemModuleExport(const char* module_name, LPCSTR routine_name);
    ULONG64 GetModuleBase64(PEPROCESS proc, UNICODE_STRING module_name);
    DWORD GetModuleBase32(PEPROCESS proc, UNICODE_STRING module_name);
    PVOID GetProcessBaseAddress(int pid);
    DWORD GetUserDirectoryTableBaseOffset();
    ULONG_PTR GetProcessCr3(PEPROCESS pprocess);
    ULONG_PTR GetKernelDirBase();
    NTSTATUS ReadVirtual(UINT64 dirbase, UINT64 address, UINT8* buffer, SIZE_T size, SIZE_T* read);
    NTSTATUS WriteVirtual(UINT64 dirbase, UINT64 address, UINT8* buffer, SIZE_T size, SIZE_T* written);
    NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead);
    NTSTATUS WritePhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten);
    UINT64 TranslateLinearAddress(UINT64 directoryTableBase, UINT64 virtualAddress);
    NTSTATUS ReadProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size);
    NTSTATUS WriteProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size);
    BOOL WriteMemory(void* address, void* buffer, size_t size);
    BOOL WriteToReadOnlyMemory(void* address, void* buffer, size_t size);
}

typedef struct vicidataptr
{
    void* buffer_address;
    UINT_PTR address;
    ULONGLONG size;
    ULONG pid;
    BOOLEAN write;
    BOOLEAN read;
    BOOLEAN req_base;
    void* output;
    const char* module_name;
    ULONG64 base_address;

}vicidataptr;