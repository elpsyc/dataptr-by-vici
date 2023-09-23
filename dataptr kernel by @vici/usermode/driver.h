#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

extern DWORD64 ProcessId;
extern DWORD64 ModuleBase;

typedef struct _NULL_MEMORY
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
}NULL_MEMORY;

class DRIVERFUNC {
public:

	template<typename T> bool write(uint64_t Address, const T& _Value)
	{
		return WriteMemory(Address, (UINT_PTR)&_Value, sizeof(T));
	}
	template<typename T> bool write(uint32_t Address, const T& _Value)
	{
		return WriteMemory(__int64(Address), (UINT_PTR)&_Value, sizeof(T));
	}
	template<typename T> T read(uint64_t Address)
	{
		T _Value;
		ReadMemory(Address, &_Value, sizeof(T));
		return _Value;
	}
	template<typename T> T read(uint32_t Address)
	{
		T _Value;
		ReadMemory(__int64(Address), &_Value, sizeof(T));
		return _Value;
	}
	template<typename T> T APIread(HANDLE Handle, uint64_t Address)
	{
		T _Value;
		ReadProcessMemory(Handle, (LPCVOID)(Address), &_Value, sizeof(T), NULL);
		return _Value;
	}
	template<typename T> T APIread(HANDLE Handle, uint32_t Address)
	{
		T _Value;
		ReadProcessMemory(Handle, (LPCVOID)(Address), &_Value, sizeof(T), NULL);
		return _Value;
	}

	void InitDriver();
	void ReadMemory(UINT_PTR read_address, void* buffer, size_t size);
	std::string ReadString(UINT_PTR address);
	std::string ReadStringPointer(UINT_PTR address);
	BOOL WriteMemory(UINT_PTR write_address, UINT_PTR source_address, SIZE_T write_size);
	DWORD64 GetModuleBase(const char* module_name);
	uint32_t GetPID(const wchar_t* processName);
};

extern DRIVERFUNC vicidataptr;