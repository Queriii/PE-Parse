#include "stdafx.h"



#define ERROR_PROLOGUE TEXT(".-. Error .-.\nCode: 0x")
bool DisplayError(ULONG ulExceptionCode, DWORD dwAdditionalComments = NULL, ...)
{
	if (ulExceptionCode == NULL)			//Indicates that a previous DisplayError call failed, in this case dwAdditionalComments will contain the original exception code...
	{
		TCHAR ErrorMessageBuffer[9] = {};
		if (_stprintf_s(ErrorMessageBuffer, _countof(ErrorMessageBuffer), TEXT("%X"), dwAdditionalComments) == -1)
		{
			return false;
		}
		MessageBox(nullptr, ErrorMessageBuffer, TEXT("Additional error occurred during DisplayError..."), MB_OK | MB_TOPMOST);
		return true;
	}
	else
	{
		if (dwAdditionalComments == NULL)
		{
			size_t ErrorMessageBufferLength = _tcslen(ERROR_PROLOGUE) + 9;
			TCHAR* ErrorMessageBuffer = new TCHAR[ErrorMessageBufferLength]{};
			if (ErrorMessageBuffer == nullptr)
			{
				return false;
			}

			bool Err = false;
			__try
			{
				if (_tcscpy_s(ErrorMessageBuffer, ErrorMessageBufferLength, ERROR_PROLOGUE))
				{
					Err = true;
					__leave;
				}
				if (_stprintf_s(ErrorMessageBuffer + _tcslen(ERROR_PROLOGUE), ErrorMessageBufferLength - _tcslen(ErrorMessageBuffer), TEXT("%X"), ulExceptionCode) == -1)
				{
					Err = true;
					__leave;
				}
				MessageBox(nullptr, ErrorMessageBuffer, TEXT(":("), MB_OK | MB_TOPMOST);
			}
			__finally
			{
				if (ErrorMessageBuffer)
				{
					delete[] ErrorMessageBuffer;
				}
			}

			return !Err;
		}
		else
		{
			size_t ErrorMessageBufferLength = _tcslen(ERROR_PROLOGUE) + 9;
			TCHAR* ErrorMessageBuffer = new TCHAR[ErrorMessageBufferLength]{};
			if (ErrorMessageBuffer == nullptr)
			{
				return false;
			}

			bool Err = false;
			__try
			{
				if (_tcscpy_s(ErrorMessageBuffer, ErrorMessageBufferLength, ERROR_PROLOGUE))
				{
					Err = true;
					__leave;
				}

				if (_stprintf_s(ErrorMessageBuffer + _tcslen(ERROR_PROLOGUE), ErrorMessageBufferLength - _tcslen(ErrorMessageBuffer), TEXT("%X"), ulExceptionCode) == -1)
				{
					Err = true;
					__leave;
				}

				va_list Ap;
				va_start(Ap, dwAdditionalComments);
				__try
				{
					for (; dwAdditionalComments > 0; dwAdditionalComments--)
					{
						TCHAR* AdditionalComment = va_arg(Ap, TCHAR*);
						ErrorMessageBufferLength += _tcslen(AdditionalComment) + 1;

						TCHAR* RelocatedErrorMessageBuffer = new TCHAR[ErrorMessageBufferLength];
						if (RelocatedErrorMessageBuffer == nullptr)
						{
							Err = true;
							__leave;
						}

						if (_tcscpy_s(RelocatedErrorMessageBuffer, ErrorMessageBufferLength, ErrorMessageBuffer))
						{
							if (RelocatedErrorMessageBuffer)
							{
								delete[] RelocatedErrorMessageBuffer;
							}
							Err = true;
							__leave;
						}

						if (ErrorMessageBuffer)
						{
							delete[] ErrorMessageBuffer;
						}
						ErrorMessageBuffer = RelocatedErrorMessageBuffer;

						if (_tcscat_s(ErrorMessageBuffer, ErrorMessageBufferLength, TEXT("\n")))
						{
							Err = true;
							__leave;
						}
						if (_tcscat_s(ErrorMessageBuffer, ErrorMessageBufferLength, AdditionalComment))
						{
							Err = true;
							__leave;
						}
					}
				}
				__finally
				{
					va_end(Ap);
				}

				if (!Err)
				{
					MessageBox(nullptr, ErrorMessageBuffer, TEXT(":("), MB_OK | MB_TOPMOST);
				}
			}
			_finally
			{
				if (ErrorMessageBuffer)
				{
					delete[] ErrorMessageBuffer;
				}
			}

			return !Err;
		}
	}
}



ULONG UnableToDisplayError(ULONG ulExceptionCode)				//Probably should never happen...
{
	_tprintf(TEXT("DisplayError failed twice...\nOriginal Error Code: %X"), ulExceptionCode);
	return EXCEPTION_EXECUTE_HANDLER;
}



TCHAR* FormatGetLastErrorCode(DWORD dwGetLastErrorCode)
{
	TCHAR GetLastErrorCodeBuffer[9] = {};
	if (_itot_s(dwGetLastErrorCode, GetLastErrorCodeBuffer, _countof(GetLastErrorCodeBuffer), 16))
	{
		return nullptr;
	}

	TCHAR GLECPrologue[] = TEXT("GetLastErrorCode: 0x");
	size_t GLECErrorMessageSize = _tcslen(GLECPrologue) + _tcslen(GetLastErrorCodeBuffer) + 1;
	TCHAR* GLECErrorMessage = new TCHAR[GLECErrorMessageSize]{};
	if (GLECErrorMessage == nullptr)
	{
		return nullptr;
	}

	bool Err = false;
	__try
	{
		if (_tcscpy_s(GLECErrorMessage, GLECErrorMessageSize, GLECPrologue))
		{
			Err = true;
			__leave;
		}
		if (_tcscat_s(GLECErrorMessage, GLECErrorMessageSize, GetLastErrorCodeBuffer))
		{
			Err = true;
			__leave;
		}
	}
	__finally
	{
		if (Err)
		{
			delete[] GLECErrorMessage;
			GLECErrorMessage = nullptr;
		}
	}

	return GLECErrorMessage;
}



ULONG GLECLogOnly(DWORD dwGetLastErrorCode, ULONG ulExceptionCode)
{
	TCHAR* GLECComment = FormatGetLastErrorCode(dwGetLastErrorCode);
	if (GLECComment)
	{
		__try
		{
			if (!DisplayError(ulExceptionCode, 1, GLECComment))
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

	if (!DisplayError(ulExceptionCode))
	{
		if (!DisplayError(NULL, ulExceptionCode))
		{
			return UnableToDisplayError(ulExceptionCode);
		}
	}
	return EXCEPTION_EXECUTE_HANDLER;
}
