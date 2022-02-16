#pragma once
#include <wdm.h>

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
}KAPC_ENVIRONMENT, * PKAPC_ENVIRONMENT;

typedef void (NTAPI *_KeInitializeApc)(
	PRKAPC Apc,
	PRKTHREAD Thread,
	UINT32 Environment,
	PVOID KernelRoutine,
	PVOID RundownRoutine,
	PVOID NormalRoutine,
	KPROCESSOR_MODE ProcessorMode,
	PVOID NormalContext
);

typedef BOOLEAN (NTAPI *_KeInsertQueueApc)(
	PRKAPC Apc,
	PVOID SystemArgument1,
	PVOID SystemArgument2,
	KPRIORITY Increment);


typedef PCHAR(NTAPI *_PsGetProcessImageFileName)(PEPROCESS Process);

extern "C" PVOID NTAPI RtlImageDirectoryEntryToData (
	PVOID  		BaseAddress,
	BOOLEAN  	MappedAsImage,
	USHORT  	Directory,
	PULONG  	Size 
);

extern "C" void LoadLibrary_stub();

// from minwindef.h
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned long       DWORD;

// from winnt.h
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;