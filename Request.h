#pragma once



#include "stdafx.h"



struct Request
{
	TCHAR* szFunction;
	
	DWORD dwArgs;
	TCHAR** pArgs;		//Array of args...

	Request(const TCHAR* szCommand)
	{
		DWORD CommandLength	= NULL;
		DWORD NumOfArgs			= NULL;

		bool ArgFlags			= false;
		for (DWORD CommandIndex = 0; CommandIndex < _tcslen(szCommand); CommandIndex++)
		{
			if (!ArgFlags)
			{
				if (szCommand[CommandIndex] == TEXT(' '))
				{
					ArgFlags = true;
				}
				else
				{
					CommandLength++;
				}
			}
			else
			{
				if (szCommand[CommandIndex] == TEXT(' ') || CommandIndex >= _tcslen(szCommand) - 1)
				{
					NumOfArgs++;
				}
			}
		}
		dwArgs = NumOfArgs;

		szFunction = new TCHAR[CommandLength + 1]{};
		_tcsncpy_s(szFunction, CommandLength + 1, szCommand, CommandLength);

		DWORD* ArgLengths = new DWORD[NumOfArgs]{};
		if (ArgFlags)
		{
			for (DWORD CommandIndex = CommandLength + 1, CurrentArg = 0; CommandIndex < _tcslen(szCommand) && CurrentArg < NumOfArgs; CommandIndex++)
			{
				if (szCommand[CommandIndex] == TEXT(' '))
				{
					CurrentArg++;
				}
				else
				{
					ArgLengths[CurrentArg] += 1;
				}
			}

			DWORD AmtToOffset = CommandLength + 1;
			pArgs = new TCHAR * [NumOfArgs];
			for (DWORD CurrentArg = 0; CurrentArg < NumOfArgs; CurrentArg++)
			{
				pArgs[CurrentArg] = new TCHAR[ArgLengths[CurrentArg] + 1]{};
				_tcsncpy_s(pArgs[CurrentArg], ArgLengths[CurrentArg] + 1, szCommand + AmtToOffset, ArgLengths[CurrentArg]);
				AmtToOffset += (ArgLengths[CurrentArg] + 1);
			}
		}
		else
		{
			pArgs = nullptr;
		}
	}

	~Request()
	{
		if (szFunction)
		{
			delete[] szFunction;
		}

		for (DWORD i = 0; i < dwArgs; i++)
		{
			if (pArgs[i])
			{
				delete[] pArgs[i];
			}
		}
	}
};