#include <Ntifs.h>
#include "misc.h"

_PsGetProcessImageFileName PsGetProcessImageFileName = nullptr;
_KeInitializeApc KeInitializeApc = nullptr;
_KeInsertQueueApc KeInsertQueueApc = nullptr;

VOID APCLevelRoutine(PRKAPC Apc, PVOID *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1, PVOID *SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	ExFreePool(Apc);
}

VOID PassiveLevelRoutine(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	// NormalContext should be a baseaddress of kernel32
	if (!NormalContext) return;

	// Query LoadLibraryA address
	PVOID LoadLibraryAAddr = nullptr;
	auto baseaddr = reinterpret_cast<char*>(NormalContext);

	ULONG size = 0;
	auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(RtlImageDirectoryEntryToData(baseaddr, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size));
	if (!exports) return;

	auto *ordinals  = reinterpret_cast<short*>(baseaddr + exports->AddressOfNameOrdinals);
	auto *funcnames = reinterpret_cast<DWORD*>(baseaddr + exports->AddressOfNames);
	auto *funcaddrs = reinterpret_cast<DWORD*>(baseaddr + exports->AddressOfFunctions);
	if (!ordinals || !funcnames || !funcaddrs) return;

	for (DWORD i = 0; i < exports->NumberOfFunctions; i++) {
		if (strcmp(baseaddr + funcnames[i], "LoadLibraryA")) continue;

		LoadLibraryAAddr = baseaddr + funcaddrs[ordinals[i]];
		break;
	}

	PVOID shellcode = nullptr;
	SIZE_T Size = 4096; //1-Page is enough to execute this shellcode
	if (!NT_SUCCESS(ZwAllocateVirtualMemory(ZwCurrentProcess(), &shellcode, 0, &Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE))) return;
	RtlCopyMemory(shellcode, LoadLibrary_stub, 128); // actually 36 bytes

	PKAPC Apc = reinterpret_cast<PKAPC>(ExAllocatePool(NonPagedPool, sizeof(KAPC)));
	if (!Apc) {
		ZwFreeVirtualMemory(ZwCurrentProcess(), &shellcode, &Size, MEM_RELEASE);
		return;
	}

	KeInitializeApc(Apc, PsGetCurrentThread(), CurrentApcEnvironment, APCLevelRoutine, nullptr, shellcode, UserMode, LoadLibraryAAddr);
	if (!KeInsertQueueApc(Apc, nullptr, nullptr, 0)) ExFreePool(Apc);
}

void LoadImageCallback(_In_ PUNICODE_STRING FullImageName, _In_  HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo)
{
	UNREFERENCED_PARAMETER(ImageInfo);

	// we dont have to check system.
	if (ImageInfo->SystemModeImage) return;
	
	// check dll name
	wchar_t* bs = wcsrchr(FullImageName->Buffer, L'\\');
	if (_wcsicmp(bs, L"\\kernel32.dll")) return;

	// check process name
	PEPROCESS procinfo = nullptr;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &procinfo))) return;
	
	auto filename = PsGetProcessImageFileName(procinfo);
	if (!filename) goto END;

	if (_stricmp(filename, "notepad.exe")) goto END;


	PKAPC apc = reinterpret_cast<PKAPC>(ExAllocatePool(NonPagedPool, sizeof(KAPC)));
	if (!apc) goto END;

	// APC level routine does nothing, passive level routine queues a usermode apc.
	KeInitializeApc(apc, KeGetCurrentThread(), OriginalApcEnvironment, APCLevelRoutine, nullptr, 
					PassiveLevelRoutine, KernelMode, ImageInfo->ImageBase);

	if (!KeInsertQueueApc(apc, nullptr, nullptr, 0)) ExFreePool(apc);

END:
	ObDereferenceObject(procinfo);
}

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	PsRemoveLoadImageNotifyRoutine(LoadImageCallback);
}

extern "C" DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	UNICODE_STRING function_str1 = RTL_CONSTANT_STRING(L"PsGetProcessImageFileName");
	UNICODE_STRING function_str2 = RTL_CONSTANT_STRING(L"KeInitializeApc");
	UNICODE_STRING function_str3 = RTL_CONSTANT_STRING(L"KeInsertQueueApc");

	PsGetProcessImageFileName	= reinterpret_cast<_PsGetProcessImageFileName>(MmGetSystemRoutineAddress(&function_str1));
	KeInitializeApc				= reinterpret_cast<_KeInitializeApc>(MmGetSystemRoutineAddress(&function_str2));
	KeInsertQueueApc			= reinterpret_cast<_KeInsertQueueApc>(MmGetSystemRoutineAddress(&function_str3));
	if (!PsGetProcessImageFileName || !KeInitializeApc || !KeInsertQueueApc) {
		return STATUS_ACCESS_DENIED; // which status should I return?
	}

	NTSTATUS ret = PsSetLoadImageNotifyRoutine(LoadImageCallback);
	if (!NT_SUCCESS(ret)) return ret;

	DriverObject->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;
}