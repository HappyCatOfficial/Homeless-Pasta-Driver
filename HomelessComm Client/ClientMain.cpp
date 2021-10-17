#include <Windows.h>
#include <iostream>
#include <random>

HKEY registry_handle = nullptr;
std::string registry_key{ };

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

bool InitRegConnection() {
	const char* sreg_key = "gaylond";//change this if u want in this and driver too
	auto status = RegOpenKeyExA(HKEY_CURRENT_USER, sreg_key, 0, KEY_ALL_ACCESS, &registry_handle);
	HKEY hKey{};
	if (status != ERROR_SUCCESS)
	{
		HKEY pRegKey;
		LONG lRtnVal = 0;
		DWORD Disposition;

		lRtnVal = RegCreateKeyExA(
			HKEY_CURRENT_USER,
			sreg_key,
			0,
			NULL,
			REG_OPTION_VOLATILE,
			KEY_ALL_ACCESS,
			NULL,
			&pRegKey,
			&Disposition);

		if (lRtnVal != ERROR_SUCCESS) return false;

		RegCloseKey(pRegKey);
	}


	status = RegOpenKeyExA(HKEY_CURRENT_USER, sreg_key, 0, KEY_ALL_ACCESS, &registry_handle);
	if (status != ERROR_SUCCESS)
	{
		printf("Cannot open Reg connection key!\n");
		return false;
	}

	std::generate_n(std::back_inserter(registry_key), 16, []()
		{
			thread_local std::mt19937_64 mersenne_generator(std::random_device{ }());
			const std::uniform_int_distribution<> distribution(97, 122);
			return static_cast<std::uint8_t>(distribution(mersenne_generator));
		});
	return true;
}

int __stdcall main() {
	printf("Open Reg Connection to driver...\n");
	if (InitRegConnection()) {
		//Run Command:
		operation_command data = {
			(void*)0x11, //Pass hier struct pointer 
			ReqTypes::RequestRead,
			0xDEAD99
		};

		auto state = RegSetValueExA(registry_handle, registry_key.c_str(), 0, REG_BINARY, reinterpret_cast<std::uint8_t*>(&data), sizeof(data));
		printf("state: 0x%llx\n", state);
	}
	return 0;
}