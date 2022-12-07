#include "stdafx.h"

#include "ExceptionCodes.h"
#include "ErrorFormatting.h"





ULONG ExceptionHandler(ULONG ulExceptionCode, PEXCEPTION_POINTERS pExceptionInformation)
{
	switch (ulExceptionCode)
	{

	//Noncontinuables Start
	case QUERI_EXCEPTION_INVALID_STARTUP_ARGS:
	{
		if (!DisplayError(ulExceptionCode, 1, TEXT("This is likely the result of not opening PE-Parse with an additional file, or opening with multiple files...")))
		{
			if (!DisplayError(NULL, ulExceptionCode))
			{
				return UnableToDisplayError(ulExceptionCode);
			}
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}

	case QUERI_EXCEPTION_STARTUP_ARG_PATH_TOO_LONG:
	{
		if (!DisplayError(ulExceptionCode, 1, TEXT("The path of your desired file exceeds 256 characters, move the file to a directory that doesn't exceed this character limit...")))
		{
			if (!DisplayError(NULL, ulExceptionCode))
			{
				return UnableToDisplayError(ulExceptionCode);
			}
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}

	case QUERI_EXCEPTION_INVALID_FILE_HANDLE:
	{
		if (pExceptionInformation->ExceptionRecord->NumberParameters == 1)
		{
			TCHAR* GLECComment = FormatGetLastErrorCode(pExceptionInformation->ExceptionRecord->ExceptionInformation[0]);

			if (GLECComment)
			{
				__try
				{
					if (!DisplayError(ulExceptionCode, 2, TEXT("This is likely due to a lack of permissions, try running the program with elevated privileges..."), GLECComment))
					{
						if (!DisplayError(NULL, ulExceptionCode))
						{
							return UnableToDisplayError(ulExceptionCode);
						}
					}
					return EXCEPTION_EXECUTE_HANDLER;
				}
				__finally
				{
					if (GLECComment)
					{
						delete[] GLECComment;
					}
				}
			}
		}

		if (!DisplayError(ulExceptionCode, 1, TEXT("This is likely due to a lack of permissions, try running the program with elevated privileges...")))
		{
			if (!DisplayError(NULL, ulExceptionCode))
			{
				return UnableToDisplayError(ulExceptionCode);
			}
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}

	case QUERI_EXCEPTION_MAP_FILE:
	{
		if (pExceptionInformation->ExceptionRecord->NumberParameters == 1)
		{
			return GLECLogOnly(pExceptionInformation->ExceptionRecord->ExceptionInformation[0], ulExceptionCode);
		}
		if (!DisplayError(ulExceptionCode))
		{
			if (!DisplayError(NULL, ulExceptionCode))
			{
				return UnableToDisplayError(ulExceptionCode);
			}
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}

	case QUERI_EXCEPTION_MAP_FILE_VIEW:
	{
		if (pExceptionInformation->ExceptionRecord->NumberParameters == 1)
		{
			return GLECLogOnly(pExceptionInformation->ExceptionRecord->ExceptionInformation[0], ulExceptionCode);
		}
		if (!DisplayError(ulExceptionCode))
		{
			if (!DisplayError(NULL, ulExceptionCode))
			{
				return UnableToDisplayError(ulExceptionCode);
			}
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}

	case QUERI_EXCEPTION_CREATE_THREAD:
	{
		if (pExceptionInformation->ExceptionRecord->NumberParameters == 1)
		{
			return GLECLogOnly(pExceptionInformation->ExceptionRecord->ExceptionInformation[0], ulExceptionCode);
		}
		if (!DisplayError(ulExceptionCode))
		{
			if (!DisplayError(NULL, ulExceptionCode))
			{
				return UnableToDisplayError(ulExceptionCode);
			}
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}

	case QUERI_EXCEPTION_INVALID_FILE:
	{
		if (!DisplayError(ulExceptionCode, 1, TEXT("This is likely due to trying to parse a non-pe file...")))
		{
			if (!DisplayError(NULL, ulExceptionCode))
			{
				return UnableToDisplayError(ulExceptionCode);
			}
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}

	case QUERI_EXCEPTION_INVALID_ARCHITECTURE:
	{
		if (!DisplayError(ulExceptionCode, 1, TEXT("This is likely due to an invalid architecture...")))
		{
			if (!DisplayError(NULL, ulExceptionCode))
			{
				return UnableToDisplayError(ulExceptionCode);
			}
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}

	case QUERI_EXCEPTION_MEMORY_ALLOC_FAILED:
	{
		if (!DisplayError(ulExceptionCode, 1, TEXT("This could potentially be due to a lack of memory...")))
		{
			if (!DisplayError(NULL, ulExceptionCode))
			{
				return UnableToDisplayError(ulExceptionCode);
			}
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}

	case QUERI_EXCEPTION_BUFFER_SIZE_DETERM_FAILED:
	{
		if (!DisplayError(ulExceptionCode))
		{
			if (!DisplayError(NULL, ulExceptionCode))
			{
				return UnableToDisplayError(ulExceptionCode);
			}
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}
	//Noncontinuables End



	//Continuables Start
	case QUERI_EXCEPTION_UNKNOWN_REQUEST:
	{
		MessageBox(nullptr, TEXT("Unknown request..."), TEXT(":("), MB_OK | MB_TOPMOST);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	case QUERI_EXCEPTION_INVALID_ARGS:
	{
		MessageBox(nullptr, TEXT("Invalid arguments..."), TEXT(":("), MB_OK | MB_TOPMOST);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	case QUERI_EXCEPTION_DOES_NOT_CONTAIN_OPT_HDR:
	{
		MessageBox(nullptr, TEXT("There is no optional header for the specified file..."), TEXT(":("), MB_OK | MB_TOPMOST);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	case QUERI_EXCEPTION_NO_ARGS_PROVIDED:
	{
		MessageBox(nullptr, TEXT("Arguments for specified function are required, but no arguments were given..."), TEXT(":("), MB_OK | MB_TOPMOST);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	//Continuables End



	default:
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}

	}
}