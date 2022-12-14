#pragma once



#include "stdafx.h"



TCHAR* ParseDosHeader(const void* pMappedFile, Request* pCurrentRequest);
TCHAR* ParseFileHeader(const void* pMappedFile, Request* pCurrentRequest);
TCHAR* ParseOptionalHeader(const void* pMappedFile, Request* pCurrentRequest, WORD Architecture);
TCHAR* ParseSections(const void* pMappedFile, DWORD Architecture);
TCHAR* ParseImports(void* pMappedFile, Request* pCurrentRequest, WORD Architecture);
TCHAR* ParseExports(const void* pMappedFile, Request* pCurrentRequest, DWORD dwArchitecture);

WORD ValidateMappedFile(const void* pMappedFile);
