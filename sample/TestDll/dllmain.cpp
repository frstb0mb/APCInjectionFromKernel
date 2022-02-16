#include "pch.h"

HANDLE ret = nullptr;

DWORD WINAPI func(LPVOID* data)
{
	OutputDebugStringW(L"From Injected");

	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
					   DWORD  ul_reason_for_call,
					   LPVOID lpReserved
					 )
{
	
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		ret = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)func, nullptr, 0, nullptr);
		if (!ret) break;
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		if (ret) {
			if (WaitForSingleObject(ret, 10) != WAIT_OBJECT_0) TerminateThread(ret, 0);
			CloseHandle(ret);
		}
	}

	return TRUE;
}