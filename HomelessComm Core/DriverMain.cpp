#include "stdafx.h"

PCHAR LowerStr(PCHAR str) {
	for (PCHAR s = str; *s; ++s) {
		*s = (CHAR)tolower(*s);
	}
	return str;
}

PVOID GetBaseAddress(PCHAR name, PULONG outSize) {
	PVOID addr = 0;

	ULONG size = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		//printf("! ZwQuerySystemInformation for size failed: %x !\n", status);
		return addr;
	}

	PSYSTEM_MODULE_INFORMATION modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, size);
	if (!modules) {
		//printf("! failed to allocate %d bytes for modules !\n", size);
		return addr;
	}

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, 0))) {
		//printf("! ZwQuerySystemInformation failed: %x !\n", status);
		ExFreePool(modules);
		return addr;
	}

	for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
		SYSTEM_MODULE m = modules->Modules[i];

		if (strstr(LowerStr((PCHAR)m.FullPathName), name)) {
			addr = m.ImageBase;
			if (outSize) {
				*outSize = m.ImageSize;
			}
			break;
		}
	}

	ExFreePool(modules);
	return addr;
}

inline auto is_specific_section(IMAGE_SECTION_HEADER section, const char* target) -> bool
{
	if (_stricmp(reinterpret_cast<const char*>(section.Name), target) == 0)
	{
		return true;
	}

	return false;
}

void* trampoline_at(void* base_address, const char* target)
{
	static const auto ntoskrnl_base = *reinterpret_cast<const char**>(std::uintptr_t(PsLoadedModuleList) + 0x30);

	const auto nt_header = RtlImageNtHeader(base_address);

	if (!nt_header)
		return nullptr;

	const auto section_array = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_header + 1);

	for (auto section = 0; section < nt_header->FileHeader.NumberOfSections; section++)
	{
		const auto current = section_array[section];

		if (current.VirtualAddress == 0 || current.Misc.VirtualSize == 0)
			continue;

		if (!(is_specific_section(current, target)))
			continue;

		const auto section_address = reinterpret_cast<char*>(base_address) + current.VirtualAddress;

		for (auto i = section_address; i < (section_address + current.SizeOfRawData) - 1; ++i)
		{
			if (!i)
				continue;

			if (*reinterpret_cast<std::uint16_t*>(i) == 0xe1ff) {
				return i;
			}
		}
	}
	return nullptr;
}

static BOOLEAN is_retop(_In_ BYTE op)
{
	return op == 0xC2 ||   // RETN + POP
		op == 0xC3 ||      // RETN
		op == 0xCA ||      // RETF + POP
		op == 0xCB;        // RETF
}

static UINT64 find_codecave(_In_ VOID* module, _In_ INT length, _In_opt_ UINT64 begin)
{
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module;
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)dos_header + dos_header->e_lfanew);

	UINT64 start = 0, size = 0;

	UINT64 header_offset = (UINT64)IMAGE_FIRST_SECTION(nt_headers);
	for (INT x = 0; x < nt_headers->FileHeader.NumberOfSections; ++x)
	{
		IMAGE_SECTION_HEADER* header = (IMAGE_SECTION_HEADER*)header_offset;

		if (strcmp((CHAR*)header->Name, ".text") == 0)
		{
			start = (UINT64)module + header->PointerToRawData;
			size = header->SizeOfRawData;
			break;
		}

		header_offset += sizeof(IMAGE_SECTION_HEADER);
	}

	UINT64 match = 0;
	INT curlength = 0;
	BOOLEAN ret = FALSE;

	for (UINT64 cur = (begin ? begin : start); cur < start + size; ++cur)
	{
		if (!ret && is_retop(*(BYTE*)cur)) ret = TRUE;
		else if (ret && *(BYTE*)cur == 0xCC)
		{
			if (!match) match = cur;
			if (++curlength == length) return match;
		}

		else
		{
			match = curlength = 0;
			ret = FALSE;
		}
	}

	return 0;
}


enum ReqTypes
{
	RequestRead,
	RequestWrite,
	RequestModule,
	RequestFree,
	RequestAlloc,
};

typedef struct operation_command {
	PVOID args;
	UINT type;
	INT64 IdCode;
};

NTSTATUS callback(void* context, void* call_reason, void* key_data)
{
	UNREFERENCED_PARAMETER(context);
	auto return_value = STATUS_SUCCESS;
	if (reinterpret_cast<std::uint64_t>(call_reason) == RegNtPreSetValueKey)
	{
		const auto key_value = static_cast<PREG_SET_VALUE_KEY_INFORMATION>(key_data);

		if (key_value->DataSize >= sizeof(operation_command))
		{
			const auto operation_data_cmd = static_cast<operation_command*>(key_value->Data);
			if (operation_data_cmd->IdCode == 0xDEAD99) {
				switch (operation_data_cmd->type)
				{
				case ReqTypes::RequestRead: {
					DbgPrintEx(0, 0, "Usermode send: 0x%llx\n", operation_data_cmd->args);
					break;
				}
				default:
					break;
				}
			}
		}
	}
	return return_value;
}

NTSTATUS DrvEntryFunction(void* start_address) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG DriverSize;
	const auto DriverBase = GetBaseAddress((PCHAR)"mouclass.sys", &DriverSize);
	if (DriverBase)
	{
		const auto trampoline = trampoline_at(DriverBase, "PAGE");
		if (!trampoline)
			return 1;

		ULONG CaveDriverSize;
		const auto CaveDriverBase = GetBaseAddress((PCHAR)"ws2ifsl.sys", &DriverSize); // replace ws2ifsl.sys with any driver you want that is unknown or just scan for all loaded drivers and check for PG protection!
		if (!CaveDriverBase) {
			DbgPrintEx(0, 0, "CaveDriver not loaded\n");
			return 2;
		}
		BYTE shellcode[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
		*(PVOID*)&shellcode[2] = &callback;
		auto resultcave = find_codecave(CaveDriverBase, sizeof(shellcode), 0); //replace this if you want with a better method!
		DbgPrintEx(0, 0, "resultcave: 0x%llx\n", resultcave);
		{
			ULONG cr0 = __readcr0();
			cr0 = cr0 & ~0x10000;
			__writecr0(cr0);
		}
		memcpy((void*)resultcave, shellcode, sizeof(shellcode));
		{
			ULONG cr0 = __readcr0();
			cr0 = cr0 | 0x10000;
			__writecr0(cr0);
		}
		LARGE_INTEGER cookie{ };
		return CmRegisterCallback(static_cast<PEX_CALLBACK_FUNCTION>(trampoline), reinterpret_cast<void*>(resultcave), &cookie);
	}
	return 3;
}