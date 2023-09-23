#include "driver.h"

DWORD64 ModuleBase{};
DWORD64 ProcessId{};

typedef INT64(*Nt_)(uintptr_t);
Nt_ Nt = nullptr;

typedef struct DRIVERINFO
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
}KOTO;
void  DRIVERFUNC::InitDriver()
{
	LoadLibrary(L"win32u.dll");
	LoadLibrary(L"User32.dll");

	Nt = (Nt_)GetProcAddress(GetModuleHandleA("win32u.dll"), "NtMITPostThreadEventMessage");
}
uint32_t DRIVERFUNC::GetPID(const wchar_t* processName)
{
	PROCESSENTRY32 procEntry32;
	uintptr_t pID = 0;

	procEntry32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (!hProcSnap || hProcSnap == INVALID_HANDLE_VALUE)
		return 0;

	while (Process32Next(hProcSnap, &procEntry32))
	{
		if (!wcscmp(processName, procEntry32.szExeFile))
		{
			pID = procEntry32.th32ProcessID;

			CloseHandle(hProcSnap);
		}
	}

	CloseHandle(hProcSnap);
	return pID;
}
DWORD64 DRIVERFUNC::GetModuleBase(const char* module_name)
{
	KOTO instructions;
	instructions = { 0 };
	instructions.pid = ProcessId;
	instructions.req_base = TRUE;
	instructions.read = FALSE;
	instructions.write = FALSE;
	instructions.module_name = module_name;
	Nt(reinterpret_cast<uintptr_t>(&instructions));

	ULONG64 base = NULL;
	base = instructions.base_address;
	return base;
}
void DRIVERFUNC::ReadMemory(UINT_PTR read_address, void* buffer, size_t size)
{
	KOTO instructions;
	instructions.pid = ProcessId;
	instructions.size = size;
	instructions.address = read_address;
	instructions.read = TRUE;
	instructions.write = FALSE;
	instructions.req_base = FALSE;
	instructions.output = buffer;
	Nt(reinterpret_cast<uintptr_t>(&instructions));
}
BOOL DRIVERFUNC::WriteMemory(UINT_PTR write_address, UINT_PTR source_address, SIZE_T write_size)
{
	KOTO instructions;
	instructions.address = write_address;
	instructions.pid = ProcessId;
	instructions.write = TRUE;
	instructions.read = FALSE;
	instructions.req_base = FALSE;
	instructions.buffer_address = (void*)source_address;
	instructions.size = write_size;

	Nt(reinterpret_cast<uintptr_t>(&instructions));

	return true;
}
std::string DRIVERFUNC::ReadString(UINT_PTR address) {
	KOTO instructions;

	std::vector<char> buffer(sizeof(std::string), char{ 0 });

	instructions.pid = ProcessId;
	instructions.size = buffer.size();
	instructions.address = address;
	instructions.read = TRUE;
	instructions.write = FALSE;
	instructions.req_base = FALSE;
	instructions.output = static_cast<void*>(&buffer[0]);

	Nt(reinterpret_cast<uintptr_t>(&instructions));

	return std::string(buffer.data());
}
std::string DRIVERFUNC::ReadStringPointer(UINT_PTR address) {
	if (read<int>(address + 0x10) > 15)
		address = read<uint32_t>(address);
	std::string res;
	char buf;
	for (int i = 0; i < 0x1000; i++) {
		buf = read<char>(address + i);
		if (!buf)
			break;
		res += buf;
	}
	return res;
}

DRIVERFUNC vicidataptr;

