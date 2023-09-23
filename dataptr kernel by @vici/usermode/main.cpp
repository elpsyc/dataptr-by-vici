#include <iostream>
#include "driver.h"

int main()
{
	vicidataptr.InitDriver();

	ProcessId = vicidataptr.GetPID(L"notepad.exe");

	printf("Pid %d\n", ProcessId);

	ModuleBase = vicidataptr.GetModuleBase("notepad.exe");

	printf("Base : % llX\n", ModuleBase);

	system("pause");

	return 0;
}

