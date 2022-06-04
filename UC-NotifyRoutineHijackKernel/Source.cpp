#include <ntifs.h>
#include <windef.h>
#define RVA(addr, size) ((uintptr_t)((uintptr_t)(addr) + *(PINT)((uintptr_t)(addr) + ((size) - sizeof(INT))) + (size)))


#define ABSOLUTE(wait) (wait)
#define RELATIVE(wait) (-(wait))
#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILLISECONDS(1000L))

typedef struct _SYSTEM_MODULE_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

extern "C" {
	NTSTATUS NTAPI ZwQuerySystemInformation(_In_ ULONG SystemInformationClass, _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);
};

typedef signed __int64* __fastcall ExReferenceCallBackBlock_t(signed __int64* a1);
typedef signed __int64 __fastcall ExDereferenceCallBackBlock_t(signed __int64* a1, __int64 a2);

NTSTATUS find_kernel_module(const char* moduleName, uintptr_t* moduleStart, size_t* moduleSize) {
	DWORD size = 0x0;
	ZwQuerySystemInformation((0xB), nullptr, size, reinterpret_cast<PULONG>(&size));

	auto listHeader = ExAllocatePool(NonPagedPool, size);

	if (!listHeader)
		return STATUS_MEMORY_NOT_ALLOCATED;


	if (const auto status = ZwQuerySystemInformation((0xB), listHeader, size, reinterpret_cast<PULONG>(&size))) {
		ExFreePoolWithTag(listHeader, 0);
		return status;
	}

	auto currentModule = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Module;

	for (size_t i{}; i < reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Count; ++i, ++currentModule) {
		const auto currentModuleName = reinterpret_cast<const char*>(currentModule->FullPathName + currentModule->OffsetToFileName);
		if (strstr(moduleName, currentModuleName)) {
			*moduleStart = reinterpret_cast<uintptr_t>(currentModule->ImageBase);
			*moduleSize = currentModule->ImageSize;
			ExFreePoolWithTag(listHeader, 0);
			return STATUS_SUCCESS;
		}
	}
	ExFreePoolWithTag(listHeader, 0);
	return STATUS_NOT_FOUND;
}

bool data_compare(const char* pdata, const char* bmask, const char* szmask)
{
	for (; *szmask; ++szmask, ++pdata, ++bmask)
	{
		if (*szmask == ("x")[0] && *pdata != *bmask)
			return false;
	}

	return !*szmask;
}

__forceinline uintptr_t find_pattern(const uintptr_t base, const size_t size, const char* bmask, const char* szmask)
{
	for (size_t i = 0; i < size; ++i)
		if (data_compare(reinterpret_cast<const char*>(base + i), bmask, szmask))
			return base + i;

	return 0;
}

LONG64 ThreadNotifyCallbackDataPtr;
void (*CreateThreadNotifyRoutineOriginal)(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);
void CreateThreadNotifyRoutineHook(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
	DbgPrintEx(0, 0, "Enter CreateThreadNotifyRoutineHook\n");
	static int iSkipFirst = 0;
	if (iSkipFirst < 10)
	{
		iSkipFirst++;
		return CreateThreadNotifyRoutineOriginal(ProcessId, ThreadId, Create);
	}

	auto PreviousMode = ExGetPreviousMode();
	if (PreviousMode == UserMode || PreviousMode == MaximumMode) { //maybe also "|| Create" but then it takes loop to start the loop because most CreateThreadNotifyRoutine calls are for create.
		return CreateThreadNotifyRoutineOriginal(ProcessId, ThreadId, Create);
	}

	*(LONG64*)(ThreadNotifyCallbackDataPtr + 8) = (LONG64)CreateThreadNotifyRoutineOriginal;

	LARGE_INTEGER Timeout500MS;
	Timeout500MS.QuadPart = RELATIVE(MILLISECONDS(500));
	DbgPrintEx(0, 0, "Start loop\n");
	while (true)
	{
		//blabal
		KeDelayExecutionThread(KernelMode, FALSE, &Timeout500MS);
		DbgPrintEx(0, 0, "+\n");
	}
}

NTSTATUS DriverStart() {
	size_t NtKrlSize = 0;
	uintptr_t NtKrlBase = 0;
	auto ntstatus = find_kernel_module("ntoskrnl.exe", &NtKrlBase, &NtKrlSize);
	if (NT_SUCCESS(ntstatus))
	{
		auto PspCreateThreadNotifyRoutineInst = (ULONG64)find_pattern(NtKrlBase, NtKrlSize, ("\x48\x8D\x0D\x00\x00\x00\x00\x45\x33\xC0\x48\x8D\x0C\xD9\x48\x8B\xD7\xE8\x00\x00\x00\x00\x84\xC0\x75\x0C"), ("xxx????xxxxxxxxxxx????xxxx")); //2004 - win11
		if (!PspCreateThreadNotifyRoutineInst || !MmIsAddressValid((void*)PspCreateThreadNotifyRoutineInst))
		{
			return STATUS_NOT_FOUND;
		}
		PRTL_RUN_ONCE PspCreateThreadNotifyRoutine = (PRTL_RUN_ONCE)RVA(PspCreateThreadNotifyRoutineInst, 7);
		if (!PspCreateThreadNotifyRoutine || !MmIsAddressValid((void*)PspCreateThreadNotifyRoutine))
		{
			return STATUS_NOT_FOUND + 1;
		}

		auto ExReferenceCallBackBlockInst = (ULONG64)find_pattern(NtKrlBase, NtKrlSize, ("\xE8\x00\x00\x00\x00\x48\x8B\xE8\x48\x85\xC0\x74\x66\x48\x8B\x40\x08\x4D\x8B\xC4\x48\x8B\x4D\x10"), ("x????xxxxxxxxxxxxxxxxxxx")); //2004 - win11
		if (!ExReferenceCallBackBlockInst || !MmIsAddressValid((void*)ExReferenceCallBackBlockInst))
		{
			return STATUS_NOT_FOUND + 2;
		}
		ExReferenceCallBackBlock_t* ExReferenceCallBackBlock = (ExReferenceCallBackBlock_t*)RVA(ExReferenceCallBackBlockInst, 5);
		if (!ExReferenceCallBackBlock || !MmIsAddressValid((void*)ExReferenceCallBackBlock))
		{
			return STATUS_NOT_FOUND + 3;
		}

		auto ExDereferenceCallBackBlockInst = (ULONG64)find_pattern(NtKrlBase, NtKrlSize, ("\x8B\xF8\xE8\x00\x00\x00\x00\x48\x8D\x54\x24\x00\x48\x8B\xCE"), ("xxx????xxxx?xxx")); //2004 - win11
		if (!ExDereferenceCallBackBlockInst || !MmIsAddressValid((void*)ExDereferenceCallBackBlockInst))
		{
			return STATUS_NOT_FOUND + 2;
		}
		ExDereferenceCallBackBlockInst += 0x2;

		ExDereferenceCallBackBlock_t* ExDereferenceCallBackBlock = (ExDereferenceCallBackBlock_t*)RVA(ExDereferenceCallBackBlockInst, 5);
		if (!ExDereferenceCallBackBlock || !MmIsAddressValid((void*)ExDereferenceCallBackBlock))
		{
			return STATUS_NOT_FOUND + 3;
		}

		int i = 0;
		while (true)
		{
			if ((unsigned int)i >= 0x40)
			{
				break;
			}
			if (auto Callback = ExReferenceCallBackBlock((signed __int64*)&PspCreateThreadNotifyRoutine->Ptr + i))
			{
				if (!Callback || !MmIsAddressValid((void*)Callback))
				{
					continue;
				}
				else
				{
					ThreadNotifyCallbackDataPtr = (LONG64)Callback;
					auto ThreadCallbackFunctionAddr = *(LONG64*)(ThreadNotifyCallbackDataPtr + 8);
					*(LONG64*)&CreateThreadNotifyRoutineOriginal = ThreadCallbackFunctionAddr;
					*(LONG64*)(ThreadNotifyCallbackDataPtr + 8) = (LONG64)&CreateThreadNotifyRoutineHook;

					ExDereferenceCallBackBlock((signed __int64*)&PspCreateThreadNotifyRoutine->Ptr + i, (__int64)Callback);
					DbgPrintEx(0, 0, "CreateThreadNotifyRoutine Hooked\n");
					return STATUS_SUCCESS;
				}
			}
			i++;
		}
	}
	return STATUS_UNSUCCESSFUL;
}