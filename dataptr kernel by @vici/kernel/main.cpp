#include "utils.h"
#include "memory.h"
#define printf(...) DbgPrintEx( DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, "[+] Unknown [+]" __VA_ARGS__ )

#define SIG (xorstr("\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x10\x44\x8B\x54\x24\x00\x44\x89\x54\x24\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x38\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x48"))
#define SIG_MASK (xorstr("xxx????xxxxxxxxx?xxxx?xx????xxxxxxxxxxxxxxxx"))

__int64(__fastcall* Nt)(void* a1);

#define DECRYPT_CR3(cr3, key, v36) (cr3 & 0xBFFF000000000FFF) | (((key ^ v36 ^ (v36 << 32)) & 0xFFFFFFFFF) << 12)

bool IsCr3Invalid(uintptr_t cr3)
{
	return (cr3 >> 0x38) == 0x40;
}


uintptr_t EAC_Cr3 = 0;
PEPROCESS Saved_Process = 0;

ULONG_PTR memory::GetProcessCr3(PEPROCESS pProcess)
{

    ULONG_PTR process_dirbase = *(PULONG_PTR)((PUCHAR)pProcess + 0x28); //dirbase x64, 32bit is 0x18
    if (process_dirbase == 0)
    {
        DWORD UserDirOffset = memory::GetUserDirectoryTableBaseOffset();
        ULONG_PTR process_dirbase = *(PULONG_PTR)((PUCHAR)pProcess + UserDirOffset);
    }
    if (IsCr3Invalid(process_dirbase))
    {
        if (Saved_Process != pProcess)
        {
            uintptr_t eac_module = utils::get_kernel_module(xorstr("EasyAntiCheat_EOS.sys"));

            if (!eac_module)
                return process_dirbase;

            uintptr_t offset = *(LONGLONG*)(eac_module + 0x1706A8);
            if (!offset)
                return process_dirbase;

            LONGLONG data_offset = (offset & 0xFFFFFFFFF) << 12;
            LONGLONG data = ((0xFFFFull << 48) + data_offset);

            LONGLONG key = *(LONGLONG*)(data + 0x14);

            LONGLONG eacaddress = (((LONGLONG)(eac_module + 0x18F7A0) ^ ((LONGLONG)(eac_module + 0x18F7A0) << 13)) >> 7) ^ (LONGLONG)(eac_module + 0x18F7A0) ^ ((LONGLONG)(eac_module + 0x18F7A0) << 13);
            LONGLONG v32 = eacaddress ^ (eacaddress << 17);

            EAC_Cr3 = DECRYPT_CR3(process_dirbase, key, v32);

            Saved_Process = pProcess;
        }

        if (Saved_Process == pProcess)
            process_dirbase = EAC_Cr3;
    }

    return process_dirbase;
}

NTSTATUS HookHandler(PVOID called_param)
{
    vicidataptr* vici = (vicidataptr*)called_param;

    if (vici->req_base != FALSE)
    {
        ANSI_STRING AS;
        UNICODE_STRING ModuleName;

        RtlInitAnsiString(&AS, vici->module_name);
        RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);

        PEPROCESS process;
        PsLookupProcessByProcessId((HANDLE)vici->pid, &process);
        ULONG64 base_address64 = NULL;
        base_address64 = memory::GetModuleBase64(process, ModuleName);
        vici->base_address = base_address64;
        RtlFreeUnicodeString(&ModuleName);
    }

    if (vici->write != FALSE)
    {
        memory::WriteProcessMemory(vici->pid, (PVOID)vici->address, vici->buffer_address, vici->size);
    }

    if (vici->read != FALSE)
    {
        memory::ReadProcessMemory(vici->pid, (PVOID)vici->address, vici->output, vici->size);
    }

    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING reg_path)
{
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(reg_path);

    uintptr_t nt_qword{};

    const uintptr_t win32k = utils::get_kernel_module(xorstr("win32k.sys"));
    if (!win32k) {
        printf("win32k.sys not found\n");
        return 1;
    }

    if (win32k) {
        nt_qword = utils::pattern_scan(win32k, SIG, SIG_MASK);
        printf("found datapointer\n");
        if (!nt_qword) {
            printf("datapointer not found\n");
            return 1;
        }
    }


    const uintptr_t nt_qword_deref = (uintptr_t)nt_qword + *(int*)((BYTE*)nt_qword + 3) + 7;
    *(void**)&Nt = _InterlockedExchangePointer((void**)nt_qword_deref, (void*)HookHandler);

    printf("driver loaded\n");
    printf("by @vici._._.\n");
	return STATUS_SUCCESS;
}