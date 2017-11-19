#include <windows.h>

int main()
{
	WinExec("calc.exe",0x01010101);
	ExitThread(0);
	return 0;
}