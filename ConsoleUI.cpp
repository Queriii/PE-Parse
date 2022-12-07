#include "stdafx.h"

#include "Request.h"
#include "Parse.h"
#include "ExceptionCodes.h"



#define INSTRUCT_BUFFER_LENGTH 30
namespace Instructions 
{
	constexpr const TCHAR* DosHeader = TEXT("/DosHdr");
	constexpr const TCHAR* FileHeader = TEXT("/FileHdr");
	constexpr const TCHAR* OptionalHeader = TEXT("/OptHdr");
	constexpr const TCHAR* Sections = TEXT("/Sections");
	constexpr const TCHAR* Imports = TEXT("/Imports");
	constexpr const TCHAR* Exports = TEXT("/Exports");
	constexpr const TCHAR* Save = TEXT("/Save");
}

static const TCHAR* MenuDisplay =
TEXT(R"(Mapped File Address: 0x%p  | File Architecture: 0x%X
---------------------------------------------------------------------------
[END] - Exit  | [DEL] - Clear Screen | [Insert] - Refresh Instruction
---------------------------------------------------------------------------
/DosHdr		[-resolve]
/FileHdr	[-resolve]
/OptHdr		[-resolve]
/Sections
/Imports	
/Exports	
/Save		[-full, -recent]

)");


struct ThreadParam
{
	HANDLE*			pThreadHandle;
	const void*		pMappedFile;
	WORD			wArchitectureHexRepresentation;

	ThreadParam(HANDLE* pDefThreadHandle, const void* pDefMappedFile, WORD wDefArchitectureHexRepresentation)
		: pThreadHandle(pDefThreadHandle), pMappedFile(pDefMappedFile), wArchitectureHexRepresentation(wDefArchitectureHexRepresentation) {}
};
DWORD WINAPI WatchExit(PVOID pThreadParameter)
{
	ThreadParam* Info = reinterpret_cast<ThreadParam*>(pThreadParameter);

	for (;;)
	{
		if (GetAsyncKeyState(VK_END) & 1)
		{
			break;
		}

		if (GetAsyncKeyState(VK_DELETE) & 1)
		{
			system("CLS");
			_tprintf(TEXT(">>> "));
		}

		if (GetAsyncKeyState(VK_INSERT) & 1)
		{
			_tprintf(TEXT("\n\n\n"));
			_tprintf(MenuDisplay, Info->pMappedFile, Info->wArchitectureHexRepresentation);
			_tprintf(TEXT(">>> "));
		}
		Sleep(500);
	}

	if (Info->pThreadHandle)
	{
		if (*(Info->pThreadHandle) && *(Info->pThreadHandle) != INVALID_HANDLE_VALUE)
		{
			CloseHandle(*(Info->pThreadHandle));
		}
	}

	exit(EXIT_SUCCESS);
}



void ParseMenu(void* pMappedFile)
{
	WORD Architecture = ValidateMappedFile(pMappedFile);
	WORD ArchitectureHexRepresentation = NULL;
	if (Architecture == IMAGE_FILE_MACHINE_AMD64)
	{
		ArchitectureHexRepresentation = 0x64;
	}
	else if (Architecture == IMAGE_FILE_MACHINE_I386)
	{
		ArchitectureHexRepresentation = 0x86;
	}



	HANDLE ExitThread = nullptr;
	ThreadParam PassMe(&ExitThread, pMappedFile, ArchitectureHexRepresentation);
	ExitThread = CreateThread(nullptr, 0, WatchExit, &PassMe, NULL, nullptr);
	if (!ExitThread)
	{
		ULONG_PTR ExceptionInformation[] = { GetLastError() };
		RaiseException(QUERI_EXCEPTION_CREATE_THREAD, EXCEPTION_NONCONTINUABLE, _countof(ExceptionInformation), ExceptionInformation);
	}


	_tprintf(MenuDisplay, pMappedFile, ArchitectureHexRepresentation);
	for (;;)
	{
		fseek(stdin, 0, SEEK_END);

		_tprintf(TEXT(">>> "));
		TCHAR InstructionBuffer[INSTRUCT_BUFFER_LENGTH] = {};
		_fgetts(InstructionBuffer, INSTRUCT_BUFFER_LENGTH, stdin);
		if (InstructionBuffer[_tcslen(InstructionBuffer) - 1] == TEXT('\n')) { InstructionBuffer[_tcslen(InstructionBuffer) - 1] = TEXT('\0'); };



		Request CurrentRequest(InstructionBuffer);
		if (!_tcscmp(CurrentRequest.szFunction, Instructions::DosHeader))
		{
			TCHAR* DosHeader = ParseDosHeader(pMappedFile, &CurrentRequest);
			if (DosHeader)
			{
				_tprintf(DosHeader);
				_tprintf(TEXT("\n"));
				delete[] DosHeader;
			}
		}
		else if (!_tcscmp(CurrentRequest.szFunction, Instructions::FileHeader))
		{
			TCHAR* FileHeader = ParseFileHeader(pMappedFile, &CurrentRequest);
			if (FileHeader)
			{
				_tprintf(FileHeader);
				_tprintf(TEXT("\n"));
				delete[] FileHeader;
			}
		}
		else if (!_tcscmp(CurrentRequest.szFunction, Instructions::OptionalHeader))
		{
			TCHAR* OptionalHeader = ParseOptionalHeader(pMappedFile, &CurrentRequest, Architecture);
			if (OptionalHeader)
			{
				_tprintf(OptionalHeader);
				_tprintf(TEXT("\n"));
				delete[] OptionalHeader;
			}
		}
		else if (!_tcscmp(CurrentRequest.szFunction, Instructions::Sections))
		{
			TCHAR* Sections = ParseSections(pMappedFile, Architecture);
			if (Sections)
			{
				_tprintf(Sections);
				_tprintf(TEXT("\n"));
				delete[] Sections;
			}
		}
		else if (!_tcscmp(CurrentRequest.szFunction, Instructions::Imports))
		{
			TCHAR* Imports = ParseImports(pMappedFile, &CurrentRequest, Architecture);
			if (Imports)
			{
				_tprintf(Imports);
				_tprintf(TEXT("\n"));
				delete[] Imports;
			}
		}
		else if (!_tcscmp(CurrentRequest.szFunction, Instructions::Exports))
		{

		}
		else if (!_tcscmp(CurrentRequest.szFunction, Instructions::Save))
		{

		}
		else
		{
			RaiseException(QUERI_EXCEPTION_UNKNOWN_REQUEST, NULL, NULL, nullptr);
		}
	}
}