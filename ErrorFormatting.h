#pragma once



#include "stdafx.h"



bool DisplayError(ULONG ulExceptionCode, DWORD dwAdditionalComments = NULL, ...);
ULONG UnableToDisplayError(ULONG ulExceptionCode);
TCHAR* FormatGetLastErrorCode(DWORD dwGetLastErrorCode);
ULONG GLECLogOnly(DWORD dwGetLastErrorCode, ULONG ulExceptionCode);