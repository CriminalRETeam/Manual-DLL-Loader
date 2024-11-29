#ifndef LOADER_H
#define LOADER_H

#include <cstdio>
#include <Windows.h>

//dllmain pointer
typedef BOOL(WINAPI* dllmain)(HINSTANCE dll, DWORD reason, LPVOID reserved);

typedef unsigned long DWORD_PTR;

//Structure relocation entry based on : https://docs.microsoft.com/fr-fr/windows/win32/debug/pe-format#the-reloc-section-image-only
typedef struct IMAGE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, * PIMAGE_RELOCATION_ENTRY;

class ILoaderCallBacks
{
public:
	virtual ~ILoaderCallBacks() { }
	virtual HMODULE VLoadLibraryA(const char* pDll) = 0;
	virtual FARPROC VGetProcAddress(HMODULE hModule, const char* pFuncName) = 0;
};

class DefaultLoaderCallBacks : public ILoaderCallBacks
{
public:
	virtual HMODULE VLoadLibraryA(const char* pDll) 
	{
		return ::LoadLibraryA(pDll);
	}

	virtual FARPROC VGetProcAddress(HMODULE hModule, const char* pFuncName)
	{
		return ::GetProcAddress(hModule, pFuncName);
	}
};

class MemoryLoader
{
public:
	static LPVOID LoadDLL(const LPSTR lpDLLPath, ILoaderCallBacks& callBacks = DefaultLoaderCallBacks());
	static LPVOID GetFunctionAddress(const LPVOID lpModule, const LPSTR lpFunctionName);
	static LPVOID GetFunctionAddressByOrdinal(const LPVOID lpModule, const DWORD_PTR dOrdinal);
	static BOOL FreeDLL(const LPVOID lpModule);

private:
	static HANDLE GetFileContent(const LPSTR lpFilePath);
	static BOOL IsValidPE(const LPVOID lpImage);
	static BOOL IsDLL(const LPVOID hDLLData);
	static BOOL IsValidArch(const LPVOID lpImage);
	static DWORD_PTR GetImageSize(const LPVOID lpImage);
	static BOOL HasCallbacks(const LPVOID lpImage);
};

#endif