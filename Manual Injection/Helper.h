#pragma once
#include <iostream>
#include <Windows.h>

using namespace std;


// dll entrypoint template (see typedef function pointers)
typedef INT(__stdcall* dllmain)(HMODULE, DWORD32, LPVOID);

// sections offset
struct sectiondata {
	DWORD virtualOffset;
	DWORD rawOffset;
};

// dll entrypoint parameters
struct entrypointparams {
	intptr_t ImageBase;
	DWORD AddressOfEntryPoint;
};

// parameters for "libraryloader()" 
struct loaderdata {
	LPVOID ImageBase; //base address of dll 
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR ImportDir;
	sectiondata reloc;
	sectiondata idata;
	HANDLE hProc;
	DWORD procId;
};

bool wpmErrorHandler(bool wProcess)
{
	if (wProcess == 0) // Failed to write memory
	{
		cout << "WriteProcessMemory failed. GetLastError = " << dec << GetLastError() << "\n";
		system("pause");
		return 1;
	}
	else
	{
		return wProcess;
	}
}

template <typename T>
void printValue(const T& value)
{
	cout << "Type: " << typeid(value).name() << "\n";
	cout << "Value: " << dec << value << "\n";
	cout << "Address: " << hex << value << "\n";
}

wstring PcharToWstr(PCHAR txt)
{
	// PCHAR converted to string
	string str(txt);
	// string to wstring
	wstring wstr(str.begin(), str.end());

	return wstr;
}

DWORD FindProcessId(std::wstring processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processSnapshot);
			return processInfo.th32ProcessID;
		}
	}
	CloseHandle(processSnapshot);
	return 0;
}

uintptr_t GetModuleBaseAddress(DWORD procId, wstring modName)
{
	uintptr_t modBaseAddr = { 0 };
	
	HANDLE moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (moduleSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	MODULEENTRY32 modEntry;
	modEntry.dwSize = sizeof(modEntry);

	Module32First(moduleSnapshot, &modEntry);
	if (!_wcsicmp(modName.c_str(), modEntry.szModule))
	{
		CloseHandle(moduleSnapshot);
		modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
		return modBaseAddr;
	}

	while (Module32Next(moduleSnapshot, &modEntry))
	{
		if (!_wcsicmp(modName.c_str(), modEntry.szModule))
		{
			CloseHandle(moduleSnapshot);
			modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
			return modBaseAddr;
		}
	}
	CloseHandle(moduleSnapshot);
	return 0;
}

int ListModuleNames(DWORD procId)
{
	uintptr_t modBaseAddr = { 0 };

	HANDLE moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (moduleSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	MODULEENTRY32 modEntry;
	modEntry.dwSize = sizeof(modEntry);

	Module32First(moduleSnapshot, &modEntry);
	std::wstring firstModName = modEntry.szModule;

	while (Module32Next(moduleSnapshot, &modEntry))
	{
		modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
		wcout << hex << modBaseAddr << " - "  << modEntry.szModule << "\n";

		
		if (!firstModName.compare(modEntry.szModule))
		{
			CloseHandle(moduleSnapshot);
			return 0;
		}
	}
	CloseHandle(moduleSnapshot);
	return 0;
}

int GetSectionData(PIMAGE_NT_HEADERS ntheaders, const char * sectionName, OUT sectiondata &sdata)
{
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(ntheaders);
	for (int i = 0; i < ntheaders->FileHeader.NumberOfSections; i++)
	{
		if (!strcmp((PCHAR)pSectionHeader[i].Name, sectionName))
		{
			sdata.virtualOffset = pSectionHeader[i].VirtualAddress;
			sdata.rawOffset = pSectionHeader[i].PointerToRawData;

			return 0;
		}
	}

	return false;
}

DWORD CalculateFileOffset(DWORD RVA, sectiondata sdata)
{
	return ((RVA - sdata.virtualOffset) + sdata.rawOffset);
}

bool GetProcAddressA_WOW64(HANDLE hProcess, DWORD procId, uintptr_t dllBaseAddress, const char * szFunc, LPVOID &pOut)
{
	// Read Target Exe's headers
	BYTE * pBuf = new BYTE[0x1000];
	if (!ReadProcessMemory(hProcess, (LPCVOID) dllBaseAddress, pBuf, 0x1000, nullptr))
	{
		delete[] pBuf;
		return false;
	}

	PIMAGE_DOS_HEADER TargetDosHeader = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS TargetNTheaders = (PIMAGE_NT_HEADERS)((LPBYTE)pBuf + TargetDosHeader->e_lfanew);
	_IMAGE_DATA_DIRECTORY TargetExportDir = TargetNTheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	uintptr_t ExpSize = TargetExportDir.Size;
	uintptr_t ExpRVA = TargetExportDir.VirtualAddress;

	if (!ExpSize)
	{
		delete[] pBuf;
		return false;
	}

	BYTE * pExpDirBuf = new BYTE[ExpSize];
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pExpDirBuf);
	if (!ReadProcessMemory(hProcess, (BYTE*)dllBaseAddress + ExpRVA, pExpDirBuf, ExpSize, nullptr))
	{
		delete[] pExpDirBuf;
		delete[] pBuf;
		return false;
	}
	
	// pBase = pExpDirBuf - ExpRVA so we use pExpDirBuf i/o dllBaseAddress
	intptr_t pBase = (intptr_t)(pExpDirBuf - ExpRVA);

	// Forwarded function functor
	auto Forwarded = [&](DWORD FuncRVA) -> BYTE*
	{
		char pFullExport[MAX_PATH]{ 0 };
		auto len_out = strlen(reinterpret_cast<char*>(pBase + FuncRVA));
		if (!len_out)
			return nullptr;

		memcpy(pFullExport, reinterpret_cast<char*>(pBase + FuncRVA), len_out);
		char * pFuncName = strchr(pFullExport, '.');
		*pFuncName++ = '\0';
		if (*pFuncName == '#')
			pFuncName = reinterpret_cast<char*>(LOWORD(atoi(++pFuncName)));

		void * pOut = nullptr;
		char pDllName[MAX_PATH]{ 0 };
		strcpy_s(pDllName, pFullExport);
		strcat_s(pDllName, ".dll");
		wcout << "Forwarded: " << pDllName << " - " << pFuncName << "\n";
		//GetProcAddressA_WOW64(hProc, GetModuleHandleExA(hProc, pFullExport), pFuncName, pOut);
		GetProcAddressA_WOW64(hProcess, procId, GetModuleBaseAddress(procId, PcharToWstr(pDllName)), pFuncName, pOut);
		return reinterpret_cast<BYTE*>(pOut);
	};

	// check if exported by ordinal
	if (reinterpret_cast<UINT_PTR>(szFunc) <= MAXWORD)
	{
		WORD Base = LOWORD(pExportDir->Base - 1);
		WORD Ordinal = LOWORD(szFunc) - Base;
		DWORD FuncRVA = reinterpret_cast<DWORD*>(pBase + pExportDir->AddressOfFunctions)[Ordinal];

		delete[] pExpDirBuf;
		delete[] pBuf;

		// check if forwarded function
		if (FuncRVA >= ExpRVA && FuncRVA < ExpRVA + ExpSize)
		{
			pOut = (BYTE*)Forwarded(FuncRVA);
			return (pOut != nullptr);
		}

		pOut = reinterpret_cast<BYTE*>(dllBaseAddress) + FuncRVA;

		return true;
	}

	int max = pExportDir->NumberOfNames - 1;
	int min = 0;
	WORD Ordinal = 0;

	while (min <= max)
	{
		int mid = (min + max) >> 1;

		DWORD CurrNameRVA = reinterpret_cast<DWORD*>(pBase + pExportDir->AddressOfNames)[mid];
		char * szName = reinterpret_cast<char*>(pBase + CurrNameRVA);

		int cmp = strcmp(szName, szFunc);
		if (cmp < 0)
			min = mid + 1;
		else if (cmp > 0)
			max = mid - 1;
		else
		{
			Ordinal = reinterpret_cast<WORD*>(pBase + pExportDir->AddressOfNameOrdinals)[mid];
			wcout << "Export : " << szName << " - Ordinal: " << dec << Ordinal << " - Position: " << mid << "\n";
			break;
		}
	}

	if (!Ordinal)
	{
		delete[] pExpDirBuf;
		delete[] pBuf;

		return false;
	}

	DWORD FuncRVA = reinterpret_cast<DWORD*>(pBase + pExportDir->AddressOfFunctions)[Ordinal];

	// check if forwarded function
	if (FuncRVA >= ExpRVA && FuncRVA < ExpRVA + ExpSize)
	{
		pOut = (BYTE*)Forwarded(FuncRVA);
		return (pOut != nullptr);
	}

	pOut = reinterpret_cast<BYTE*>(dllBaseAddress) + FuncRVA;

	delete[] pExpDirBuf;
	delete[] pBuf;

	return 0;
}

bool PatchImportSection(LPVOID Memory)
{
	// C-style casting. Struct pointer(loaderdata*) implies the size of struct in memory
	loaderdata* LoaderParams = (loaderdata*)Memory;

	// Resolve DLL imports
	PIMAGE_IMPORT_DESCRIPTOR ImportDesc = LoaderParams->ImportDir;

	while (ImportDesc->Characteristics) {
		ImportDesc->OriginalFirstThunk = CalculateFileOffset(ImportDesc->OriginalFirstThunk, LoaderParams->idata);
		ImportDesc->FirstThunk = CalculateFileOffset(ImportDesc->FirstThunk, LoaderParams->idata);
		ImportDesc->Name = CalculateFileOffset(ImportDesc->Name, LoaderParams->idata);

		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + ImportDesc->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + ImportDesc->FirstThunk);	// Function addresses to be fixed

		// Target module base address
		uintptr_t dllBaseAddress = GetModuleBaseAddress(LoaderParams->procId, PcharToWstr((PCHAR)((intptr_t)LoaderParams->ImageBase + ImportDesc->Name)));
		wcout << "DLL Name: " << (PCHAR)((intptr_t)LoaderParams->ImageBase + ImportDesc->Name) << "\n";

		while (OrigFirstThunk->u1.AddressOfData)
		{
			LPVOID pOut = { 0 };
			OrigFirstThunk->u1.AddressOfData = CalculateFileOffset(OrigFirstThunk->u1.AddressOfData, LoaderParams->idata);
			FirstThunk->u1.AddressOfData = CalculateFileOffset(FirstThunk->u1.AddressOfData, LoaderParams->idata);
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal (not tested yet because of lack of example)
				wcout << "Ordinal: " << OrigFirstThunk->u1.Ordinal << "\n";

				GetProcAddressA_WOW64(LoaderParams->hProc, LoaderParams->procId, dllBaseAddress, (PCHAR)(OrigFirstThunk->u1.Ordinal & 0xFFFF), pOut);
				wcout << "Function address: " << hex << (intptr_t)pOut << "\n";

				if (!pOut)
					return FALSE;

				FirstThunk->u1.Function = (intptr_t)pOut;
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)LoaderParams->ImageBase + OrigFirstThunk->u1.AddressOfData);
				wcout << "Import : " << pIBN->Name << " - Hint: " << dec <<  pIBN->Hint << "\n";

				GetProcAddressA_WOW64(LoaderParams->hProc, LoaderParams->procId, dllBaseAddress, (PCHAR)pIBN->Name, pOut);
				wcout << "Function address: " << hex << (intptr_t)pOut << "\n";

				if (!pOut)
					return FALSE;

				FirstThunk->u1.Function = (intptr_t)pOut;

			}
			OrigFirstThunk++;
			FirstThunk++;
		}
		ImportDesc++;
	}

	return 0;
}

bool FixRelocSection(LPVOID Memory, LPVOID ExeImage)
{
	// C-style casting. Struct pointer(loaderdata*) implies the size of struct in memory
	loaderdata* LoaderParams = (loaderdata*)Memory;

	// Fix Relocations
	PIMAGE_BASE_RELOCATION ImageReloc = LoaderParams->BaseReloc;
	ImageReloc->VirtualAddress = CalculateFileOffset(LoaderParams->BaseReloc->VirtualAddress, LoaderParams->reloc);

	intptr_t delta = (intptr_t)((LPBYTE)ExeImage - LoaderParams->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

	while (ImageReloc->VirtualAddress)
	{
		if (ImageReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			int count = (ImageReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PWORD list = (PWORD)(ImageReloc + 1);

			for (int i = 0; i < count; i++)
			{
				if (list[i])
				{
					PDWORD ptr = (PDWORD)((LPBYTE)LoaderParams->ImageBase + (ImageReloc->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		ImageReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)ImageReloc + ImageReloc->SizeOfBlock);
		ImageReloc->VirtualAddress = CalculateFileOffset(ImageReloc->VirtualAddress, LoaderParams->reloc);
	}

	return 0;
}