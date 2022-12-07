#include "stdafx.h"

#include "ConsoleUI.h"
#include "ExceptionHandler.h"
#include "ExceptionCodes.h"



int _tmain(int argc, TCHAR *argv[])
{
	SetConsoleTitle(TEXT("PE-Parse | Queriii"));
	HANDLE Console = GetStdHandle(STD_OUTPUT_HANDLE);
	if (Console != INVALID_HANDLE_VALUE)
	{
		SetConsoleTextAttribute(Console, 3);	
	}

	__try
	{
		if (argc != 2)
		{
			RaiseException(QUERI_EXCEPTION_INVALID_STARTUP_ARGS, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
		}
		else
		{
			//Initialization begin...
			TCHAR* FilePath = argv[1];
			if (_tcslen(FilePath)+1 > MAX_PATH)
			{
				RaiseException(QUERI_EXCEPTION_STARTUP_ARG_PATH_TOO_LONG, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
			}
			HANDLE FileHandle = CreateFile(FilePath, FILE_READ_ACCESS, NULL, nullptr, OPEN_EXISTING, NULL, nullptr);
			if (FileHandle == INVALID_HANDLE_VALUE)
			{
				ULONG_PTR ExceptionInformation[] = { GetLastError() };
				RaiseException(QUERI_EXCEPTION_INVALID_FILE_HANDLE, EXCEPTION_NONCONTINUABLE, _countof(ExceptionInformation), ExceptionInformation);
			}

			HANDLE Mapped = CreateFileMapping(FileHandle, nullptr, PAGE_READONLY, NULL, NULL, nullptr);
			if (Mapped == NULL)
			{
				if (FileHandle && FileHandle != INVALID_HANDLE_VALUE)
				{
					CloseHandle(FileHandle);
				}
				ULONG_PTR ExceptionInformation[] = { GetLastError() };
				RaiseException(QUERI_EXCEPTION_MAP_FILE, EXCEPTION_NONCONTINUABLE, _countof(ExceptionInformation), ExceptionInformation);
			}
			if (FileHandle && FileHandle != INVALID_HANDLE_VALUE)
			{
				CloseHandle(FileHandle);
			}

			void* FileAddress = MapViewOfFile(Mapped, FILE_MAP_READ, NULL, NULL, NULL);
			if (!FileAddress)
			{
				ULONG_PTR ExceptionInformation[] = { GetLastError() };
				RaiseException(QUERI_EXCEPTION_MAP_FILE_VIEW, EXCEPTION_NONCONTINUABLE, _countof(ExceptionInformation), ExceptionInformation);
			}
			//Initialization end...

			ParseMenu(FileAddress);
		}
	}
	__except (ExceptionHandler(GetExceptionCode(), GetExceptionInformation())) { return 1; };
}