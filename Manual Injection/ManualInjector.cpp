#include "pch.h"
#include <iostream>
#include <string>
#include <fstream>

#include <Windows.h>
#include <Tlhelp32.h>
#include "Helper.h"

using namespace std;


// code responsible for calling the dll entry point in remote process (this will be copied to and executed in the target process)
int __stdcall CallDllEntryPoint(LPVOID Memory)
{
	// C-style casting. Struct pointer(entrypointparams*) implies the size of struct in memory
	entrypointparams* DllParams = (entrypointparams*)Memory;

	// if the dll has an entrypoint: 
	if (DllParams->AddressOfEntryPoint)
	{
		dllmain EntryPoint = (dllmain)((LPBYTE)DllParams->ImageBase + DllParams->AddressOfEntryPoint);
		return EntryPoint((HMODULE)DllParams->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}

	return true;
}

DWORD __stdcall stub()
{
	return 0;
}

int main() 
{
	bool wProcess = { 0 };
	LPCSTR DllPath = "C:\\VC2018Projects\\DLL Tutorial\\x64\\Debug\\InjectionTestDLL.dll"; // x32 "C:\\VC2018Projects\\DLL Tutorial\\Debug\\InjectionTestDLL.dll"

	HANDLE hDll = CreateFileA(DllPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);

	DWORD FileSize = GetFileSize(hDll, NULL);
	PVOID FileBuffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!FileBuffer)
		return false;

	// read the dll file to the buffer (pointer) that receives the data read from a file or device
	DWORD lpNumberOfBytesRead = 0;
	if (!ReadFile(hDll, FileBuffer, FileSize, &lpNumberOfBytesRead, NULL))
	{
		VirtualFree(FileBuffer, FileSize, MEM_RELEASE);
		return false;
	}

	// Target Dll's headers:
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	PIMAGE_NT_HEADERS Ntheaders = (PIMAGE_NT_HEADERS)((LPBYTE)FileBuffer + DosHeader->e_lfanew);

	// Open target process
	DWORD ProcessId = FindProcessId(L"Target.exe"); // ManualInjector.exe for self-injection
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId);
		
	// Calculate sections offset | file Offset = RVAOfData - Virtual Offset + Raw Offset
	loaderdata LoaderParams;
	GetSectionData(Ntheaders, ".reloc", LoaderParams.reloc);
	GetSectionData(Ntheaders, ".idata", LoaderParams.idata);

	DWORD relocOffset = CalculateFileOffset(Ntheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, LoaderParams.reloc);
	DWORD idataOffset = CalculateFileOffset(Ntheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, LoaderParams.idata);

	// initialize the parameters for PatchImportSection()
	LoaderParams.ImageBase = (LPVOID)FileBuffer;
	LoaderParams.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)FileBuffer + DosHeader->e_lfanew);
	LoaderParams.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)FileBuffer + relocOffset);
	LoaderParams.ImportDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)FileBuffer + idataOffset);
	LoaderParams.hProc = hProcess;
	LoaderParams.procId = ProcessId;

	PatchImportSection((LPVOID)&LoaderParams);

	// Allocate memory for the DLL in target process at the preferred address of the image or determined by the function
	uintptr_t ExeImage = (uintptr_t)(VirtualAllocEx(hProcess, (LPVOID)(Ntheaders->OptionalHeader.ImageBase), Ntheaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!ExeImage)
	{
		ExeImage = (uintptr_t)(VirtualAllocEx(hProcess, nullptr, Ntheaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		cout << hex << (uintptr_t)Ntheaders->OptionalHeader.ImageBase << " - Relocation needed at: " << ExeImage << "\n";
		FixRelocSection((LPVOID)&LoaderParams, (LPVOID)ExeImage);
		if (!ExeImage)
		{
			printf("Memory allocation failed (ex) 0x%X\n", GetLastError());
			VirtualFree(FileBuffer, FileSize, MEM_RELEASE);
			return false;
		}
	}

	// copy section headers to target process:
	wProcess = WriteProcessMemory(hProcess, (LPVOID)ExeImage, FileBuffer, Ntheaders->OptionalHeader.SizeOfHeaders, NULL);
	wpmErrorHandler(wProcess);

	PIMAGE_SECTION_HEADER SectHeader = (PIMAGE_SECTION_HEADER)(Ntheaders + 1); // + 1 int == DWORD to skip signature

	// copy sections of the dll to target process:
	for (int i = 0; i < Ntheaders->FileHeader.NumberOfSections; i++)
	{
		wProcess = WriteProcessMemory(
			hProcess,
			(PVOID)((LPBYTE)ExeImage + SectHeader[i].VirtualAddress),
			(PVOID)((LPBYTE)FileBuffer + SectHeader[i].PointerToRawData),
			SectHeader[i].SizeOfRawData,
			NULL
		);

		wpmErrorHandler(wProcess);
	}

	// initialize the parameters for CallDllEntryPoint()
	entrypointparams f_params;
	f_params.ImageBase = Ntheaders->OptionalHeader.ImageBase;
	f_params.AddressOfEntryPoint = Ntheaders->OptionalHeader.AddressOfEntryPoint;
	
	// Allocate Memory for CallDllEntryPoint() function code
	uintptr_t pShellcode = (uintptr_t)VirtualAllocEx(hProcess, nullptr, (DWORD)stub - (DWORD)CallDllEntryPoint, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode)
	{
		printf("Memory allocation failed (1) (ex) 0x%X\n", GetLastError());
		VirtualFree(FileBuffer, FileSize, MEM_RELEASE);
		VirtualFreeEx(hProcess, (LPVOID)ExeImage, 0, MEM_RELEASE);
		return false;
	}

	// Write parameters for CallDllEntryPoint() function to target process where DLL is initially copied. Dos Header can be overwritten except e_lfanew
	wProcess = WriteProcessMemory(hProcess, (LPVOID)ExeImage, &f_params, sizeof(entrypointparams), NULL);
	wpmErrorHandler(wProcess);

	// Write the CallDllEntryPoint() function code to target process
	wProcess = WriteProcessMemory(hProcess, (LPVOID)(pShellcode), CallDllEntryPoint, (DWORD)stub - (DWORD)CallDllEntryPoint, NULL);
	wpmErrorHandler(wProcess);

	// create remote thread to execute the loader code | C-style casting. Struct pointer (loaderdata*) implies the size of struct in memory
	//HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)((loaderdata*)LoaderMemory + 1), LoaderMemory, 0, NULL);
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(pShellcode), (LPVOID)ExeImage, 0, NULL);
	
	// Wait for the loader to finish executing
	WaitForSingleObject(hThread, INFINITE);

	cout << "Address of entrypointparams: " << hex << pShellcode << "\n";
	cout << "Address of Image: " << hex << ExeImage << "\n";
	cout << "Press any key, to exit! \n";

	cin.get();

	// free the allocated dll file read in local process, DLL image and CallDllEntryPoint() parameters and function code copied in target process
	VirtualFree(FileBuffer, FileSize, MEM_RELEASE);
	VirtualFreeEx(hProcess, (LPVOID)ExeImage, 0, MEM_RELEASE);
	VirtualFreeEx(hProcess, (LPVOID)pShellcode, 0, MEM_RELEASE);

	return 0;
}