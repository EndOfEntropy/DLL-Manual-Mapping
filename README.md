# DLL-Injector
Standard and Manual DLL injection

The manual injector loads a DLL in the target process without using the LoadLibrary API.
Fixes the relocation section.
Patches the import section assuming the required DLL is initially loaded in the target process address space. 
