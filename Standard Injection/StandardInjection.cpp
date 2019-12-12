#include "pch.h"
#include <iostream>
#include <Windows.h>

using namespace std;

int main()
{
	// path to our DLL
	LPCSTR DllPath = "C:\\VC2018Projects\\DLL Tutorial\\x64\\Debug\\InjectionTestDLL.dll";

	// Open a handle to target process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 6676); // provide valid PID

	// Allocate memory  for the Dllpath in the target process, length of hte path sting + null terminator
	LPVOID pDllPath = VirtualAllocEx(hProcess, 0, strlen(DllPath) + 1, MEM_COMMIT, PAGE_READWRITE);

	// Write the path to the address of the memory we just allocated in the target process
	WriteProcessMemory(hProcess, pDllPath, (LPVOID)DllPath, strlen(DllPath) + 1, 0);

	// Create a Remote Thread in the target process which calls LoadLibraryA as our DllPath as an argument -> program loads our Dll
	HANDLE hLoadThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), ("LoadLibraryA")), pDllPath, 0, 0);

	// Wait for the execution of our loader thread to finish
	WaitForSingleObject(hLoadThread, INFINITE);

	cout << "Dll path allocated at: " << pDllPath << "\n";
	cin.get();

	// Free the memory allocated for our dll path
	VirtualFreeEx(hProcess, pDllPath, strlen(DllPath) + 1, MEM_RELEASE);

	return 0;
}