#include "stdafx.h"

#include "ExceptionCodes.h"
#include "Request.h"


namespace Arguments
{
	constexpr const TCHAR* Resolve	= TEXT("-resolve");
}


WORD ValidateMappedFile(const void* pMappedFile)
{
	const IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(pMappedFile);
	if (DosHeader->e_magic != 0x5A4D)
	{
		RaiseException(QUERI_EXCEPTION_INVALID_FILE, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
	}

	const IMAGE_NT_HEADERS* NtHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(reinterpret_cast<const BYTE*>(pMappedFile) + DosHeader->e_lfanew);
	if (NtHeader->Signature != 0x00004550)
	{
		RaiseException(QUERI_EXCEPTION_INVALID_FILE, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
	}

	if (NtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 && NtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
	{
		RaiseException(QUERI_EXCEPTION_INVALID_ARCHITECTURE, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
	}

	return NtHeader->FileHeader.Machine;
}



TCHAR* ParseDosHeader(const void* pMappedFile, Request* pCurrentRequest)
{
	const IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(pMappedFile);

	if (pCurrentRequest->dwArgs > 0)
	{
		if (pCurrentRequest->dwArgs > 1 || _tcscmp(pCurrentRequest->pArgs[0], Arguments::Resolve))
		{
			RaiseException(QUERI_EXCEPTION_INVALID_ARGS, NULL, NULL, nullptr);
			return nullptr;
		}
		else
		{
			const void* ResolvedNtHeader = nullptr;
			if (DosHeader->e_lfanew)
			{
				ResolvedNtHeader = reinterpret_cast<const BYTE*>(pMappedFile) + DosHeader->e_lfanew;
			}

			TCHAR ParsedStringFormat[] = TEXT
			(R"(IMAGE_DOS_HEADER
{
WORD e_magic             = 0x%X;
WORD e_cblp              = 0x%X;
WORD e_cp                = 0x%X;
WORD e_crlc              = 0x%X;
WORD e_cparhdr           = 0x%X;
WORD e_minalloc          = 0x%X;
WORD e_maxalloc          = 0x%X;
WORD e_ss                = 0x%X;
WORD e_sp                = 0x%X;
WORD e_csum              = 0x%X;
WORD e_ip                = 0x%X;
WORD e_cs                = 0x%X;
WORD e_lfarlc            = 0x%X;
WORD e_ovno              = 0x%X;
WORD e_res[4]            = {0x%X, 0x%X, 0x%X, 0x%X};
WORD e_oemid             = 0x%X;
WORD e_oeminfo           = 0x%X;
WORD e_res2[10]          = {0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X};
LONG e_lfanew            = 0x%X;            
    void* NtHeaderAddr   = 0x%p;
};
)");
			size_t ParsedStringBufferSize = _sntprintf(NULL, NULL, ParsedStringFormat, DosHeader->e_magic, DosHeader->e_cblp, DosHeader->e_cp, DosHeader->e_crlc, DosHeader->e_cparhdr, DosHeader->e_minalloc, DosHeader->e_maxalloc, DosHeader->e_ss, DosHeader->e_sp, DosHeader->e_csum, DosHeader->e_ip, DosHeader->e_cs, DosHeader->e_lfarlc, DosHeader->e_ovno, DosHeader->e_res[0], DosHeader->e_res[1], DosHeader->e_res[2], DosHeader->e_res[3], DosHeader->e_oemid, DosHeader->e_oeminfo, DosHeader->e_res2[0], DosHeader->e_res2[1], DosHeader->e_res2[2], DosHeader->e_res2[3], DosHeader->e_res2[4], DosHeader->e_res2[5], DosHeader->e_res2[6], DosHeader->e_res2[7], DosHeader->e_res2[8], DosHeader->e_res2[9], DosHeader->e_lfanew, ResolvedNtHeader);
			if (!ParsedStringBufferSize)
			{
				RaiseException(QUERI_EXCEPTION_BUFFER_SIZE_DETERM_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
			}

			TCHAR* ParsedString = new TCHAR[ParsedStringBufferSize + 1]{};
			if (ParsedString == nullptr)
			{
				RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
			}

			_sntprintf_s(ParsedString, ParsedStringBufferSize + 1, ParsedStringBufferSize, ParsedStringFormat, DosHeader->e_magic, DosHeader->e_cblp, DosHeader->e_cp, DosHeader->e_crlc, DosHeader->e_cparhdr, DosHeader->e_minalloc, DosHeader->e_maxalloc, DosHeader->e_ss, DosHeader->e_sp, DosHeader->e_csum, DosHeader->e_ip, DosHeader->e_cs, DosHeader->e_lfarlc, DosHeader->e_ovno, DosHeader->e_res[0], DosHeader->e_res[1], DosHeader->e_res[2], DosHeader->e_res[3], DosHeader->e_oemid, DosHeader->e_oeminfo, DosHeader->e_res2[0], DosHeader->e_res2[1], DosHeader->e_res2[2], DosHeader->e_res2[3], DosHeader->e_res2[4], DosHeader->e_res2[5], DosHeader->e_res2[6], DosHeader->e_res2[7], DosHeader->e_res2[8], DosHeader->e_res2[9], DosHeader->e_lfanew, ResolvedNtHeader);

			return ParsedString;
		}
	}
	else
	{
		TCHAR ParsedStringFormat[] = TEXT
		(R"(IMAGE_DOS_HEADER
{
WORD e_magic       = 0x%X;
WORD e_cblp        = 0x%X;
WORD e_cp          = 0x%X;
WORD e_crlc        = 0x%X;
WORD e_cparhdr     = 0x%X;
WORD e_minalloc    = 0x%X;
WORD e_maxalloc    = 0x%X;
WORD e_ss          = 0x%X;
WORD e_sp          = 0x%X;
WORD e_csum        = 0x%X;
WORD e_ip          = 0x%X;
WORD e_cs          = 0x%X;
WORD e_lfarlc      = 0x%X;
WORD e_ovno        = 0x%X;
WORD e_res[4]      = {0x%X, 0x%X, 0x%X, 0x%X};
WORD e_oemid       = 0x%X;
WORD e_oeminfo     = 0x%X;
WORD e_res2[10]    = {0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X};
LONG e_lfanew      = 0x%X;
};
)");
		size_t ParsedStringBufferSize = _sntprintf(NULL, NULL, ParsedStringFormat, DosHeader->e_magic, DosHeader->e_cblp, DosHeader->e_cp, DosHeader->e_crlc, DosHeader->e_cparhdr, DosHeader->e_minalloc, DosHeader->e_maxalloc, DosHeader->e_ss, DosHeader->e_sp, DosHeader->e_csum, DosHeader->e_ip, DosHeader->e_cs, DosHeader->e_lfarlc, DosHeader->e_ovno, DosHeader->e_res[0], DosHeader->e_res[1], DosHeader->e_res[2], DosHeader->e_res[3], DosHeader->e_oemid, DosHeader->e_oeminfo, DosHeader->e_res2[0], DosHeader->e_res2[1], DosHeader->e_res2[2], DosHeader->e_res2[3], DosHeader->e_res2[4], DosHeader->e_res2[5], DosHeader->e_res2[6], DosHeader->e_res2[7], DosHeader->e_res2[8], DosHeader->e_res2[9], DosHeader->e_lfanew);
		if (!ParsedStringBufferSize)
		{
			RaiseException(QUERI_EXCEPTION_BUFFER_SIZE_DETERM_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
		}

		TCHAR* ParsedString = new TCHAR[ParsedStringBufferSize + 1]{};
		if (ParsedString == nullptr)
		{
			RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
		}

		_sntprintf_s(ParsedString, ParsedStringBufferSize + 1, ParsedStringBufferSize, ParsedStringFormat, DosHeader->e_magic, DosHeader->e_cblp, DosHeader->e_cp, DosHeader->e_crlc, DosHeader->e_cparhdr, DosHeader->e_minalloc, DosHeader->e_maxalloc, DosHeader->e_ss, DosHeader->e_sp, DosHeader->e_csum, DosHeader->e_ip, DosHeader->e_cs, DosHeader->e_lfarlc, DosHeader->e_ovno, DosHeader->e_res[0], DosHeader->e_res[1], DosHeader->e_res[2], DosHeader->e_res[3], DosHeader->e_oemid, DosHeader->e_oeminfo, DosHeader->e_res2[0], DosHeader->e_res2[1], DosHeader->e_res2[2], DosHeader->e_res2[3], DosHeader->e_res2[4], DosHeader->e_res2[5], DosHeader->e_res2[6], DosHeader->e_res2[7], DosHeader->e_res2[8], DosHeader->e_res2[9], DosHeader->e_lfanew);

		return ParsedString;
	}
}



TCHAR* ParseFileHeader(const void* pMappedFile, Request* pCurrentRequest)
{
	const IMAGE_DOS_HEADER*		DosHeader	= reinterpret_cast<const IMAGE_DOS_HEADER*>(pMappedFile);
	const IMAGE_NT_HEADERS64*	NtHeader	= reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const BYTE*>(pMappedFile) + DosHeader->e_lfanew);
	const IMAGE_FILE_HEADER		FileHeader	= NtHeader->FileHeader;

	if (pCurrentRequest->dwArgs > 0)
	{
		if (pCurrentRequest->dwArgs > 1 || _tcscmp(pCurrentRequest->pArgs[0], Arguments::Resolve))
		{
			RaiseException(QUERI_EXCEPTION_INVALID_ARGS, NULL, NULL, nullptr);
			return nullptr;
		}
		else
		{
			const void* ResolvedSymbolTable = nullptr;
			if (FileHeader.PointerToSymbolTable)
			{
				ResolvedSymbolTable = reinterpret_cast<const BYTE*>(pMappedFile) + FileHeader.PointerToSymbolTable;
			}

			TCHAR ParsedStringFormat[] = TEXT
			(R"(IMAGE_FILE_HEADER
{
WORD  Machine                = 0x%X;
WORD  NumberOfSections       = 0x%X;
DWORD TimeDateStamp          = 0x%X;
DWORD PointerToSymbolTable   = 0x%X;               
    void* SymbolTableAddr    = 0x%p;
DWORD NumberOfSymbols        = 0x%X;
WORD  SizeOfOptionalHeader   = 0x%X;
WORD  Characterstics         = 0x%X;
};
)");
			size_t ParsedStringBufferSize = _sntprintf(NULL, NULL, ParsedStringFormat, FileHeader.Machine, FileHeader.NumberOfSections, FileHeader.TimeDateStamp, FileHeader.PointerToSymbolTable, ResolvedSymbolTable, FileHeader.NumberOfSymbols, FileHeader.SizeOfOptionalHeader, FileHeader.Characteristics);
			if (!ParsedStringBufferSize)
			{
				RaiseException(QUERI_EXCEPTION_BUFFER_SIZE_DETERM_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
			}

			TCHAR* ParsedString = new TCHAR[ParsedStringBufferSize + 1]{};
			if (ParsedString == nullptr)
			{
				RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
			}

			_sntprintf_s(ParsedString, ParsedStringBufferSize + 1, ParsedStringBufferSize, ParsedStringFormat, FileHeader.Machine, FileHeader.NumberOfSections, FileHeader.TimeDateStamp, FileHeader.PointerToSymbolTable, ResolvedSymbolTable, FileHeader.NumberOfSymbols, FileHeader.SizeOfOptionalHeader, FileHeader.Characteristics);

			return ParsedString;
		}	
	}
	else
	{
		TCHAR ParsedStringFormat[] = TEXT
		(R"(IMAGE_FILE_HEADER
{
WORD  Machine                = 0x%X;
WORD  NumberOfSections       = 0x%X;
DWORD TimeDateStamp          = 0x%X;
DWORD PointerToSymbolTable   = 0x%X;
DWORD NumberOfSymbols        = 0x%X;
WORD  SizeOfOptionalHeader   = 0x%X;
WORD  Characterstics         = 0x%X;
};
)");
		size_t ParsedStringBufferSize = _sntprintf(NULL, NULL, ParsedStringFormat, FileHeader.Machine, FileHeader.NumberOfSections, FileHeader.TimeDateStamp, FileHeader.PointerToSymbolTable, FileHeader.NumberOfSymbols, FileHeader.SizeOfOptionalHeader, FileHeader.Characteristics);
		if (!ParsedStringBufferSize)
		{
			RaiseException(QUERI_EXCEPTION_BUFFER_SIZE_DETERM_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
		}

		TCHAR* ParsedString = new TCHAR[ParsedStringBufferSize + 1]{};
		if (ParsedString == nullptr)
		{
			RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
		}

		_sntprintf_s(ParsedString, ParsedStringBufferSize + 1, ParsedStringBufferSize, ParsedStringFormat, FileHeader.Machine, FileHeader.NumberOfSections, FileHeader.TimeDateStamp, FileHeader.PointerToSymbolTable, FileHeader.NumberOfSymbols, FileHeader.SizeOfOptionalHeader, FileHeader.Characteristics);

		return ParsedString;
	}
}



TCHAR* ParseOptionalHeader(const void* pMappedFile, Request* pCurrentRequest, WORD Architecture)
{
	const IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(pMappedFile);

	switch (Architecture)
	{

	case IMAGE_FILE_MACHINE_AMD64:
	{
		const IMAGE_NT_HEADERS64*	NtHeader		= reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const BYTE*>(DosHeader) + DosHeader->e_lfanew);
		IMAGE_OPTIONAL_HEADER64		OptionalHeader	= NtHeader->OptionalHeader;
		
		if (OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC && OptionalHeader.Magic != IMAGE_ROM_OPTIONAL_HDR_MAGIC)
		{
			RaiseException(QUERI_EXCEPTION_DOES_NOT_CONTAIN_OPT_HDR, NULL, NULL, nullptr);
			return nullptr;
		}

		if (pCurrentRequest->dwArgs > 0)
		{
			if (pCurrentRequest->dwArgs > 1 || _tcscmp(pCurrentRequest->pArgs[0], Arguments::Resolve))
			{
				RaiseException(QUERI_EXCEPTION_INVALID_ARGS, NULL, NULL, nullptr);
				return nullptr;
			}
			else
			{
				const void* ResolvedEntryPoint = nullptr;
				if (OptionalHeader.AddressOfEntryPoint)
				{
					ResolvedEntryPoint = reinterpret_cast<const BYTE*>(pMappedFile) + OptionalHeader.AddressOfEntryPoint;
				}

				const void* ResolvedBaseCode = nullptr;
				if (OptionalHeader.BaseOfCode)
				{
					ResolvedBaseCode = reinterpret_cast<const BYTE*>(pMappedFile) + OptionalHeader.BaseOfCode;
				}

				TCHAR ParsedStringFormat[] = TEXT
				(R"(IMAGE_NT_HEADERS64
{
WORD  Magic                         = 0x%X;
BYTE  MajorLinkerVersion            = 0x%X;
BYTE  MinorLinkerVersion            = 0x%X;
DWORD SizeOfCode                    = 0x%X;
DWORD SizeOfInitializedData         = 0x%X;
DWORD SizeOfUninitializedData       = 0x%X;
DWORD AddressOfEntryPoint           = 0x%X;            
    void* EntryPointAddr            = 0x%p;
DWORD BaseOfCode                    = 0x%X;            
    void* BaseOfCodeAddr            = 0x%p;
DWORD ImageBase                     = 0x%X;
DWORD SectionAlignment              = 0x%X;
DWORD FileAlignment                 = 0x%X;
WORD  MajorOperatingSystemVersion   = 0x%X;
WORD  MinorOperatingSystemVersion   = 0x%X;
WORD  MajorImageVersion             = 0x%X;
WORD  MinorImageVersion             = 0x%X;
WORD  MajorSubsystemVersion         = 0x%X;
WORD  MinorSubsystemVersion         = 0x%X;
DWORD Win32VersionValue             = 0x%X;
DWORD SizeOfImage                   = 0x%X;
DWORD SizeOfHeaders                 = 0x%X;
DWORD CheckSum                      = 0x%X;
WORD  Subsystem                     = 0x%X;
WORD  DllCharacteristics            = 0x%X;
DWORD SizeOfStackReserve            = 0x%X;
DWORD SizeOfStackCommit             = 0x%X;
DWORD SizeOfHeapReserve             = 0x%X;
DWORD SizeOfHeapCommit              = 0x%X;
DWORD LoaderFlags                   = 0x%X;
DWORD NumberOfRvaAndSizes           = 0x%X;
IMAGE_DATA_DIRECTORY* DataDirectory = 0x%p;
};
)");
				size_t ParsedStringBufferSize = _sntprintf(NULL, NULL, ParsedStringFormat, OptionalHeader.Magic, OptionalHeader.MajorLinkerVersion, OptionalHeader.MinorLinkerVersion, OptionalHeader.SizeOfCode, OptionalHeader.SizeOfInitializedData, OptionalHeader.SizeOfUninitializedData, OptionalHeader.AddressOfEntryPoint, ResolvedEntryPoint, OptionalHeader.BaseOfCode, ResolvedBaseCode, OptionalHeader.ImageBase, OptionalHeader.SectionAlignment, OptionalHeader.FileAlignment, OptionalHeader.MajorOperatingSystemVersion, OptionalHeader.MinorOperatingSystemVersion, OptionalHeader.MajorImageVersion, OptionalHeader.MinorImageVersion, OptionalHeader.MajorSubsystemVersion, OptionalHeader.MinorSubsystemVersion, OptionalHeader.Win32VersionValue, OptionalHeader.SizeOfImage, OptionalHeader.SizeOfHeaders, OptionalHeader.CheckSum, OptionalHeader.Subsystem, OptionalHeader.DllCharacteristics, OptionalHeader.SizeOfStackReserve, OptionalHeader.SizeOfStackCommit, OptionalHeader.SizeOfHeapReserve, OptionalHeader.SizeOfHeapCommit, OptionalHeader.LoaderFlags, OptionalHeader.NumberOfRvaAndSizes, OptionalHeader.DataDirectory);
				if (!ParsedStringBufferSize)
				{
					RaiseException(QUERI_EXCEPTION_BUFFER_SIZE_DETERM_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
				}

				TCHAR* ParsedString = new TCHAR[ParsedStringBufferSize + 1]{};
				if (ParsedString == nullptr)
				{
					RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
				}

				_sntprintf_s(ParsedString, ParsedStringBufferSize + 1, ParsedStringBufferSize, ParsedStringFormat, OptionalHeader.Magic, OptionalHeader.MajorLinkerVersion, OptionalHeader.MinorLinkerVersion, OptionalHeader.SizeOfCode, OptionalHeader.SizeOfInitializedData, OptionalHeader.SizeOfUninitializedData, OptionalHeader.AddressOfEntryPoint, ResolvedEntryPoint, OptionalHeader.BaseOfCode, ResolvedBaseCode, OptionalHeader.ImageBase, OptionalHeader.SectionAlignment, OptionalHeader.FileAlignment, OptionalHeader.MajorOperatingSystemVersion, OptionalHeader.MinorOperatingSystemVersion, OptionalHeader.MajorImageVersion, OptionalHeader.MinorImageVersion, OptionalHeader.MajorSubsystemVersion, OptionalHeader.MinorSubsystemVersion, OptionalHeader.Win32VersionValue, OptionalHeader.SizeOfImage, OptionalHeader.SizeOfHeaders, OptionalHeader.CheckSum, OptionalHeader.Subsystem, OptionalHeader.DllCharacteristics, OptionalHeader.SizeOfStackReserve, OptionalHeader.SizeOfStackCommit, OptionalHeader.SizeOfHeapReserve, OptionalHeader.SizeOfHeapCommit, OptionalHeader.LoaderFlags, OptionalHeader.NumberOfRvaAndSizes, OptionalHeader.DataDirectory);

				return ParsedString;
			}
		}
		else
		{
			TCHAR ParsedStringFormat[] = TEXT
			(R"(IMAGE_NT_HEADERS64
{
WORD  Magic                         = 0x%X;
BYTE  MajorLinkerVersion            = 0x%X;
BYTE  MinorLinkerVersion            = 0x%X;
DWORD SizeOfCode                    = 0x%X;
DWORD SizeOfInitializedData         = 0x%X;
DWORD SizeOfUninitializedData       = 0x%X;
DWORD AddressOfEntryPoint           = 0x%X;
DWORD BaseOfCode                    = 0x%X;
DWORD ImageBase                     = 0x%X;
DWORD SectionAlignment              = 0x%X;
DWORD FileAlignment                 = 0x%X;
WORD  MajorOperatingSystemVersion   = 0x%X;
WORD  MinorOperatingSystemVersion   = 0x%X;
WORD  MajorImageVersion             = 0x%X;
WORD  MinorImageVersion             = 0x%X;
WORD  MajorSubsystemVersion         = 0x%X;
WORD  MinorSubsystemVersion         = 0x%X;
DWORD Win32VersionValue             = 0x%X;
DWORD SizeOfImage                   = 0x%X;
DWORD SizeOfHeaders                 = 0x%X;
DWORD CheckSum                      = 0x%X;
WORD  Subsystem                     = 0x%X;
WORD  DllCharacteristics            = 0x%X;
DWORD SizeOfStackReserve            = 0x%X;
DWORD SizeOfStackCommit             = 0x%X;
DWORD SizeOfHeapReserve             = 0x%X;
DWORD SizeOfHeapCommit              = 0x%X;
DWORD LoaderFlags                   = 0x%X;
DWORD NumberOfRvaAndSizes           = 0x%X;
IMAGE_DATA_DIRECTORY* DataDirectory = 0x%p;
};
)");
			size_t ParsedStringBufferSize = _sntprintf(NULL, NULL, ParsedStringFormat, OptionalHeader.Magic, OptionalHeader.MajorLinkerVersion, OptionalHeader.MinorLinkerVersion, OptionalHeader.SizeOfCode, OptionalHeader.SizeOfInitializedData, OptionalHeader.SizeOfUninitializedData, OptionalHeader.AddressOfEntryPoint, OptionalHeader.BaseOfCode, OptionalHeader.ImageBase, OptionalHeader.SectionAlignment, OptionalHeader.FileAlignment, OptionalHeader.MajorOperatingSystemVersion, OptionalHeader.MinorOperatingSystemVersion, OptionalHeader.MajorImageVersion, OptionalHeader.MinorImageVersion, OptionalHeader.MajorSubsystemVersion, OptionalHeader.MinorSubsystemVersion, OptionalHeader.Win32VersionValue, OptionalHeader.SizeOfImage, OptionalHeader.SizeOfHeaders, OptionalHeader.CheckSum, OptionalHeader.Subsystem, OptionalHeader.DllCharacteristics, OptionalHeader.SizeOfStackReserve, OptionalHeader.SizeOfStackCommit, OptionalHeader.SizeOfHeapReserve, OptionalHeader.SizeOfHeapCommit, OptionalHeader.LoaderFlags, OptionalHeader.NumberOfRvaAndSizes, OptionalHeader.DataDirectory);
			if (!ParsedStringBufferSize)
			{
				RaiseException(QUERI_EXCEPTION_BUFFER_SIZE_DETERM_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
			}

			TCHAR* ParsedString = new TCHAR[ParsedStringBufferSize + 1]{};
			if (ParsedString == nullptr)
			{
				RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
			}

			_sntprintf_s(ParsedString, ParsedStringBufferSize + 1, ParsedStringBufferSize, ParsedStringFormat, OptionalHeader.Magic, OptionalHeader.MajorLinkerVersion, OptionalHeader.MinorLinkerVersion, OptionalHeader.SizeOfCode, OptionalHeader.SizeOfInitializedData, OptionalHeader.SizeOfUninitializedData, OptionalHeader.AddressOfEntryPoint, OptionalHeader.BaseOfCode, OptionalHeader.ImageBase, OptionalHeader.SectionAlignment, OptionalHeader.FileAlignment, OptionalHeader.MajorOperatingSystemVersion, OptionalHeader.MinorOperatingSystemVersion, OptionalHeader.MajorImageVersion, OptionalHeader.MinorImageVersion, OptionalHeader.MajorSubsystemVersion, OptionalHeader.MinorSubsystemVersion, OptionalHeader.Win32VersionValue, OptionalHeader.SizeOfImage, OptionalHeader.SizeOfHeaders, OptionalHeader.CheckSum, OptionalHeader.Subsystem, OptionalHeader.DllCharacteristics, OptionalHeader.SizeOfStackReserve, OptionalHeader.SizeOfStackCommit, OptionalHeader.SizeOfHeapReserve, OptionalHeader.SizeOfHeapCommit, OptionalHeader.LoaderFlags, OptionalHeader.NumberOfRvaAndSizes, OptionalHeader.DataDirectory);

			return ParsedString;
		}
	}

	case IMAGE_FILE_MACHINE_I386:
	{
		const IMAGE_NT_HEADERS32* NtHeader = reinterpret_cast<const IMAGE_NT_HEADERS32*>(reinterpret_cast<const BYTE*>(DosHeader) + DosHeader->e_lfanew);
		IMAGE_OPTIONAL_HEADER32	OptionalHeader = NtHeader->OptionalHeader;

		if (OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && OptionalHeader.Magic != IMAGE_ROM_OPTIONAL_HDR_MAGIC)
		{
			RaiseException(QUERI_EXCEPTION_DOES_NOT_CONTAIN_OPT_HDR, NULL, NULL, nullptr);
			return nullptr;
		}

		if (pCurrentRequest->dwArgs > 0)
		{
			if ((pCurrentRequest->dwArgs > 1) || (_tcscmp(pCurrentRequest->pArgs[0], Arguments::Resolve)))
			{
				RaiseException(QUERI_EXCEPTION_INVALID_ARGS, NULL, NULL, nullptr);
				return nullptr;
			}
			else
			{
				const void* ResolvedEntryPoint = nullptr;
				if (OptionalHeader.AddressOfEntryPoint)
				{
					ResolvedEntryPoint = reinterpret_cast<const BYTE*>(pMappedFile) + OptionalHeader.AddressOfEntryPoint;
				}

				const void* ResolvedBaseCode = nullptr;
				if (OptionalHeader.BaseOfCode)
				{
					ResolvedBaseCode = reinterpret_cast<const BYTE*>(pMappedFile) + OptionalHeader.BaseOfCode;
				}

				const void* ResolvedBaseData = nullptr;
				if (OptionalHeader.BaseOfData)
				{
					ResolvedBaseData = reinterpret_cast<const BYTE*>(pMappedFile) + OptionalHeader.BaseOfData;
				}

				TCHAR ParsedStringFormat[] = TEXT
				(R"(IMAGE_NT_HEADERS32
{
WORD  Magic                         = 0x%X;
BYTE  MajorLinkerVersion            = 0x%X;
BYTE  MinorLinkerVersion            = 0x%X;
DWORD SizeOfCode                    = 0x%X;
DWORD SizeOfInitializedData         = 0x%X;
DWORD SizeOfUninitializedData       = 0x%X;
DWORD AddressOfEntryPoint           = 0x%X;
    void* EntryPointAddr            = 0x%X;
DWORD BaseOfCode                    = 0x%X;
    void* BaseOfCodeAddr            = 0x%X;
DWORD BaseOfData                    = 0x%X;
    void* BaseOfDataAddr            = 0x%X;
DWORD ImageBase                     = 0x%X;
DWORD SectionAlignment              = 0x%X;
DWORD FileAlignment                 = 0x%X;
WORD  MajorOperatingSystemVersion   = 0x%X;
WORD  MinorOperatingSystemVersion   = 0x%X;
WORD  MajorImageVersion             = 0x%X;
WORD  MinorImageVersion             = 0x%X;
WORD  MajorSubsystemVersion         = 0x%X;
WORD  MinorSubsystemVersion         = 0x%X;
DWORD Win32VersionValue             = 0x%X;
DWORD SizeOfImage                   = 0x%X;
DWORD SizeOfHeaders                 = 0x%X;
DWORD CheckSum                      = 0x%X;
WORD  Subsystem                     = 0x%X;
WORD  DllCharacteristics            = 0x%X;
DWORD SizeOfStackReserve            = 0x%X;
DWORD SizeOfStackCommit             = 0x%X;
DWORD SizeOfHeapReserve             = 0x%X;
DWORD SizeOfHeapCommit              = 0x%X;
DWORD LoaderFlags                   = 0x%X;
DWORD NumberOfRvaAndSizes           = 0x%X;
IMAGE_DATA_DIRECTORY* DataDirectory = 0x%p;
};
)");
				size_t ParsedStringBufferSize = _sntprintf(NULL, NULL, ParsedStringFormat, OptionalHeader.Magic, OptionalHeader.MajorLinkerVersion, OptionalHeader.MinorLinkerVersion, OptionalHeader.SizeOfCode, OptionalHeader.SizeOfInitializedData, OptionalHeader.SizeOfUninitializedData, OptionalHeader.AddressOfEntryPoint, ResolvedEntryPoint, OptionalHeader.BaseOfCode, ResolvedBaseCode, OptionalHeader.BaseOfData, ResolvedBaseData, OptionalHeader.ImageBase, OptionalHeader.SectionAlignment, OptionalHeader.FileAlignment, OptionalHeader.MajorOperatingSystemVersion, OptionalHeader.MinorOperatingSystemVersion, OptionalHeader.MajorImageVersion, OptionalHeader.MinorImageVersion, OptionalHeader.MajorSubsystemVersion, OptionalHeader.MinorSubsystemVersion, OptionalHeader.Win32VersionValue, OptionalHeader.SizeOfImage, OptionalHeader.SizeOfHeaders, OptionalHeader.CheckSum, OptionalHeader.Subsystem, OptionalHeader.DllCharacteristics, OptionalHeader.SizeOfStackReserve, OptionalHeader.SizeOfStackCommit, OptionalHeader.SizeOfHeapReserve, OptionalHeader.SizeOfHeapCommit, OptionalHeader.LoaderFlags, OptionalHeader.NumberOfRvaAndSizes, OptionalHeader.DataDirectory);

				if (!ParsedStringBufferSize)
				{
					RaiseException(QUERI_EXCEPTION_BUFFER_SIZE_DETERM_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
				}

				TCHAR* ParsedString = new TCHAR[ParsedStringBufferSize + 1]{};
				if (ParsedString == nullptr)
				{
					RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
				}

				_sntprintf_s(ParsedString, ParsedStringBufferSize + 1, ParsedStringBufferSize, ParsedStringFormat, OptionalHeader.Magic, OptionalHeader.MajorLinkerVersion, OptionalHeader.MinorLinkerVersion, OptionalHeader.SizeOfCode, OptionalHeader.SizeOfInitializedData, OptionalHeader.SizeOfUninitializedData, OptionalHeader.AddressOfEntryPoint, ResolvedEntryPoint, OptionalHeader.BaseOfCode, ResolvedBaseCode, OptionalHeader.BaseOfData, ResolvedBaseData, OptionalHeader.ImageBase, OptionalHeader.SectionAlignment, OptionalHeader.FileAlignment, OptionalHeader.MajorOperatingSystemVersion, OptionalHeader.MinorOperatingSystemVersion, OptionalHeader.MajorImageVersion, OptionalHeader.MinorImageVersion, OptionalHeader.MajorSubsystemVersion, OptionalHeader.MinorSubsystemVersion, OptionalHeader.Win32VersionValue, OptionalHeader.SizeOfImage, OptionalHeader.SizeOfHeaders, OptionalHeader.CheckSum, OptionalHeader.Subsystem, OptionalHeader.DllCharacteristics, OptionalHeader.SizeOfStackReserve, OptionalHeader.SizeOfStackCommit, OptionalHeader.SizeOfHeapReserve, OptionalHeader.SizeOfHeapCommit, OptionalHeader.LoaderFlags, OptionalHeader.NumberOfRvaAndSizes, OptionalHeader.DataDirectory);

				return ParsedString;
			}
		}
		else
		{
			TCHAR ParsedStringFormat[] = TEXT
			(R"(IMAGE_NT_HEADERS32
{
WORD  Magic                         = 0x%X;
BYTE  MajorLinkerVersion            = 0x%X;
BYTE  MinorLinkerVersion            = 0x%X;
DWORD SizeOfCode                    = 0x%X;
DWORD SizeOfInitializedData         = 0x%X;
DWORD SizeOfUninitializedData       = 0x%X;
DWORD AddressOfEntryPoint           = 0x%X;
DWORD BaseOfCode                    = 0x%X;
DWORD BaseOfData                    = 0x%X;
DWORD ImageBase                     = 0x%X;
DWORD SectionAlignment              = 0x%X;
DWORD FileAlignment                 = 0x%X;
WORD  MajorOperatingSystemVersion   = 0x%X;
WORD  MinorOperatingSystemVersion   = 0x%X;
WORD  MajorImageVersion             = 0x%X;
WORD  MinorImageVersion             = 0x%X;
WORD  MajorSubsystemVersion         = 0x%X;
WORD  MinorSubsystemVersion         = 0x%X;
DWORD Win32VersionValue             = 0x%X;
DWORD SizeOfImage                   = 0x%X;
DWORD SizeOfHeaders                 = 0x%X;
DWORD CheckSum                      = 0x%X;
WORD  Subsystem                     = 0x%X;
WORD  DllCharacteristics            = 0x%X;
DWORD SizeOfStackReserve            = 0x%X;
DWORD SizeOfStackCommit             = 0x%X;
DWORD SizeOfHeapReserve             = 0x%X;
DWORD SizeOfHeapCommit              = 0x%X;
DWORD LoaderFlags                   = 0x%X;
DWORD NumberOfRvaAndSizes           = 0x%X;
IMAGE_DATA_DIRECTORY* DataDirectory = 0x%p;
};
)");
			size_t ParsedStringBufferSize = _sntprintf(NULL, NULL, ParsedStringFormat, OptionalHeader.Magic, OptionalHeader.MajorLinkerVersion, OptionalHeader.MinorLinkerVersion, OptionalHeader.SizeOfCode, OptionalHeader.SizeOfInitializedData, OptionalHeader.SizeOfUninitializedData, OptionalHeader.AddressOfEntryPoint, OptionalHeader.BaseOfCode, OptionalHeader.BaseOfData, OptionalHeader.ImageBase, OptionalHeader.SectionAlignment, OptionalHeader.FileAlignment, OptionalHeader.MajorOperatingSystemVersion, OptionalHeader.MinorOperatingSystemVersion, OptionalHeader.MajorImageVersion, OptionalHeader.MinorImageVersion, OptionalHeader.MajorSubsystemVersion, OptionalHeader.MinorSubsystemVersion, OptionalHeader.Win32VersionValue, OptionalHeader.SizeOfImage, OptionalHeader.SizeOfHeaders, OptionalHeader.CheckSum, OptionalHeader.Subsystem, OptionalHeader.DllCharacteristics, OptionalHeader.SizeOfStackReserve, OptionalHeader.SizeOfStackCommit, OptionalHeader.SizeOfHeapReserve, OptionalHeader.SizeOfHeapCommit, OptionalHeader.LoaderFlags, OptionalHeader.NumberOfRvaAndSizes, OptionalHeader.DataDirectory);

			if (!ParsedStringBufferSize)
			{
				RaiseException(QUERI_EXCEPTION_BUFFER_SIZE_DETERM_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
			}

			TCHAR* ParsedString = new TCHAR[ParsedStringBufferSize + 1]{};
			if (ParsedString == nullptr)
			{
				RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
			}

			_sntprintf_s(ParsedString, ParsedStringBufferSize + 1, ParsedStringBufferSize, ParsedStringFormat, OptionalHeader.Magic, OptionalHeader.MajorLinkerVersion, OptionalHeader.MinorLinkerVersion, OptionalHeader.SizeOfCode, OptionalHeader.SizeOfInitializedData, OptionalHeader.SizeOfUninitializedData, OptionalHeader.AddressOfEntryPoint, OptionalHeader.BaseOfCode, OptionalHeader.BaseOfData, OptionalHeader.ImageBase, OptionalHeader.SectionAlignment, OptionalHeader.FileAlignment, OptionalHeader.MajorOperatingSystemVersion, OptionalHeader.MinorOperatingSystemVersion, OptionalHeader.MajorImageVersion, OptionalHeader.MinorImageVersion, OptionalHeader.MajorSubsystemVersion, OptionalHeader.MinorSubsystemVersion, OptionalHeader.Win32VersionValue, OptionalHeader.SizeOfImage, OptionalHeader.SizeOfHeaders, OptionalHeader.CheckSum, OptionalHeader.Subsystem, OptionalHeader.DllCharacteristics, OptionalHeader.SizeOfStackReserve, OptionalHeader.SizeOfStackCommit, OptionalHeader.SizeOfHeapReserve, OptionalHeader.SizeOfHeapCommit, OptionalHeader.LoaderFlags, OptionalHeader.NumberOfRvaAndSizes, OptionalHeader.DataDirectory);



			return ParsedString;
		}
	}

	default:	//Should never happen...
	{
		RaiseException(QUERI_EXCEPTION_INVALID_ARCHITECTURE, EXCEPTION_NONCONTINUABLE, NULL, nullptr);		
	}
		
	}
}



TCHAR* FormatSections(TCHAR* szSection1, TCHAR* szSection2)
{
	size_t CombinedSize = _tcslen(szSection1) + _tcslen(szSection2) + 2;
	TCHAR* Combined		= new TCHAR[CombinedSize]{};
	if (Combined == nullptr)
	{
		return nullptr;
	}

	_tcscpy_s(Combined, CombinedSize, szSection1);
	_tcscat_s(Combined, CombinedSize, TEXT("\n"));
	_tcscat_s(Combined, CombinedSize, szSection2);

	return Combined;
}
TCHAR* ParseSections(const void* pMappedFile, DWORD Architecture)
{
	const IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(pMappedFile);
	if (Architecture != IMAGE_FILE_MACHINE_AMD64 && Architecture != IMAGE_FILE_MACHINE_I386)
	{
		RaiseException(QUERI_EXCEPTION_INVALID_ARCHITECTURE, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
	}


	DWORD SizeOfOptionalHeader = NULL;
	const BYTE* OptionalHeader = NULL;
	DWORD NumberOfSections = NULL;
	switch (Architecture)
	{

	case IMAGE_FILE_MACHINE_AMD64:
	{
		const IMAGE_NT_HEADERS64* NtHeader = reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const BYTE*>(DosHeader) + DosHeader->e_lfanew);
		SizeOfOptionalHeader = NtHeader->FileHeader.SizeOfOptionalHeader;
		OptionalHeader = reinterpret_cast<const BYTE*>(&(NtHeader->OptionalHeader));
		NumberOfSections = NtHeader->FileHeader.NumberOfSections;
		break;
	}

	case IMAGE_FILE_MACHINE_I386:
	{
		const IMAGE_NT_HEADERS32* NtHeader = reinterpret_cast<const IMAGE_NT_HEADERS32*>(reinterpret_cast<const BYTE*>(DosHeader) + DosHeader->e_lfanew);
		SizeOfOptionalHeader = NtHeader->FileHeader.SizeOfOptionalHeader;
		OptionalHeader = reinterpret_cast<const BYTE*>(&(NtHeader->OptionalHeader));
		NumberOfSections = NtHeader->FileHeader.NumberOfSections;
		break;
	}

	default:
	{
		RaiseException(QUERI_EXCEPTION_INVALID_ARCHITECTURE, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
	}

	}



	const IMAGE_SECTION_HEADER* SectionHeader	= reinterpret_cast<const IMAGE_SECTION_HEADER*>(OptionalHeader + SizeOfOptionalHeader);
	TCHAR ParsedStringFormat[] = TEXT
	(R"(%ws
Raw Data Size:       0x%X
Relocation Count:    0x%X
Line Number Count:   0x%X
)");

	TCHAR* LastStringFormat = nullptr;
	for (DWORD CurrentSection = 0; CurrentSection < NumberOfSections; CurrentSection++)
	{
		//Name formatting
		if (SectionHeader[CurrentSection].Name[0] == '\\')	//Will add support for extended section names later...
		{
			continue;
		}
		BYTE UTF8FullySizedNameBuffer[9] = {};
		if (SectionHeader[CurrentSection].Name[_countof(SectionHeader[CurrentSection].Name) - 1] != '\0')	//Section name is 8 characters...
		{
			strncpy_s(reinterpret_cast<char*>(UTF8FullySizedNameBuffer), _countof(UTF8FullySizedNameBuffer), reinterpret_cast<const char*>(SectionHeader[CurrentSection].Name), 8);	
		}
		else
		{
			strncpy_s(reinterpret_cast<char*>(UTF8FullySizedNameBuffer), _countof(UTF8FullySizedNameBuffer), reinterpret_cast<const char*>(SectionHeader[CurrentSection].Name), 8);
		}
		size_t WideBufferSize = MultiByteToWideChar(CP_UTF8, NULL, reinterpret_cast<PCCH>(SectionHeader[CurrentSection].Name), -1, nullptr, NULL);
		if (!WideBufferSize)
		{
			continue;
		}
		WCHAR* NameBuffer = new WCHAR[WideBufferSize];
		if (NameBuffer == nullptr)
		{
			RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
		}
		MultiByteToWideChar(CP_UTF8, NULL, reinterpret_cast<PCCH>(SectionHeader[CurrentSection].Name), -1, NameBuffer, WideBufferSize);

		TCHAR* ParsedString = nullptr;
		__try
		{
			size_t ParsedStringBufferSize = _sntprintf(NULL, NULL, ParsedStringFormat, NameBuffer, SectionHeader[CurrentSection].SizeOfRawData, SectionHeader[CurrentSection].NumberOfRelocations, SectionHeader[CurrentSection].NumberOfLinenumbers);
			if (!ParsedStringBufferSize)
			{
				RaiseException(QUERI_EXCEPTION_BUFFER_SIZE_DETERM_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
			}

			ParsedString = new TCHAR[ParsedStringBufferSize + 1]{};
			if (ParsedString == nullptr)
			{
				RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
			}
			_sntprintf_s(ParsedString, ParsedStringBufferSize + 1, ParsedStringBufferSize, ParsedStringFormat, NameBuffer, SectionHeader[CurrentSection].SizeOfRawData, SectionHeader[CurrentSection].NumberOfRelocations, SectionHeader[CurrentSection].NumberOfLinenumbers);
		}
		__finally
		{
			if (NameBuffer)
			{
				delete[] NameBuffer;
			}
		}
		
		if (LastStringFormat)
		{
			TCHAR* LastStringOldCopy = LastStringFormat;
			LastStringFormat = FormatSections(ParsedString, LastStringFormat);
			if (ParsedString)
			{
				delete[] ParsedString;
			}
			if (LastStringOldCopy)
			{
				delete[] LastStringOldCopy;
			}
		}
		else
		{
			LastStringFormat = ParsedString;
		}
	}

	return LastStringFormat;
}



DWORD ConvertToFileOffset(const void* pMappedFile, DWORD RelativeVirtualAddress, WORD Architecture)	//Made changes, still should work but test to make sure...
{
	const IMAGE_DOS_HEADER* DosHeader	= reinterpret_cast<const IMAGE_DOS_HEADER*>(pMappedFile);


	const IMAGE_SECTION_HEADER* CurrentSection = nullptr;
	DWORD SectionCount = NULL;


	switch (Architecture)
	{

	case IMAGE_FILE_MACHINE_AMD64:
	{
		const IMAGE_NT_HEADERS64* NtHeader = reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const BYTE*>(pMappedFile) + DosHeader->e_lfanew);
		CurrentSection = reinterpret_cast<const IMAGE_SECTION_HEADER*>(reinterpret_cast<const BYTE*>(&(NtHeader->OptionalHeader)) + NtHeader->FileHeader.SizeOfOptionalHeader);
		SectionCount = NtHeader->FileHeader.NumberOfSections;
		break;
	}

	case IMAGE_FILE_MACHINE_I386:
	{
		const IMAGE_NT_HEADERS32* NtHeader = reinterpret_cast<const IMAGE_NT_HEADERS32*>(reinterpret_cast<const BYTE*>(pMappedFile) + DosHeader->e_lfanew);
		CurrentSection = reinterpret_cast<const IMAGE_SECTION_HEADER*>(reinterpret_cast<const BYTE*>(&(NtHeader->OptionalHeader)) + NtHeader->FileHeader.SizeOfOptionalHeader);
		SectionCount = NtHeader->FileHeader.NumberOfSections;
		break;
	}

	default:
	{
		RaiseException(QUERI_EXCEPTION_INVALID_ARCHITECTURE, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
	}

	}

	for (DWORD SectionIteration = 0; SectionIteration < SectionCount; SectionIteration++, CurrentSection++)
	{
		if (CurrentSection->VirtualAddress <= RelativeVirtualAddress && RelativeVirtualAddress < (CurrentSection->VirtualAddress + CurrentSection->Misc.VirtualSize))
		{
			return (RelativeVirtualAddress - CurrentSection->VirtualAddress + CurrentSection->PointerToRawData);
		}
	}

	return NULL;		//No offset found...
}


//Memory leak issues should be fixed...
#define INDENT_AMOUNT 6
TCHAR* ParseImports(void* pMappedFile, Request* pCurrentRequest, WORD dwArchitecture)
{
	const	IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(pMappedFile);
	const	IMAGE_IMPORT_DESCRIPTOR* Imports = nullptr;



	switch (dwArchitecture)
	{

	case IMAGE_FILE_MACHINE_AMD64:
	{
		const IMAGE_NT_HEADERS64* NtHeader = reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const BYTE*>(pMappedFile) + DosHeader->e_lfanew);

		IMAGE_DATA_DIRECTORY ImageDataDirectory = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (!ImageDataDirectory.Size)
		{
			return nullptr;
		}
		Imports = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(reinterpret_cast<const BYTE*>(pMappedFile) + ConvertToFileOffset(pMappedFile, ImageDataDirectory.VirtualAddress, dwArchitecture));
		break;
	}

	case IMAGE_FILE_MACHINE_I386:
	{
		const IMAGE_NT_HEADERS32* NtHeader = reinterpret_cast<const IMAGE_NT_HEADERS32*>(reinterpret_cast<const BYTE*>(pMappedFile) + DosHeader->e_lfanew);
		IMAGE_DATA_DIRECTORY ImageDataDirectory = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (!ImageDataDirectory.Size)
		{
			return nullptr;
		}
		Imports = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(reinterpret_cast<const BYTE*>(pMappedFile) + ConvertToFileOffset(pMappedFile, ImageDataDirectory.VirtualAddress, dwArchitecture));
		break;
	}

	default:
	{
		RaiseException(QUERI_EXCEPTION_INVALID_ARCHITECTURE, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
	}

	}


	char* FormattedImports = nullptr;
	for (const IMAGE_IMPORT_DESCRIPTOR* ImportsLoop = Imports; ImportsLoop->Characteristics != NULL; ImportsLoop++)
	{
		const char* CurrentModule = reinterpret_cast<const char*>(reinterpret_cast<const BYTE*>(pMappedFile) + ConvertToFileOffset(pMappedFile, ImportsLoop->Name, dwArchitecture));
		if (FormattedImports == nullptr)
		{
			size_t FormattedImportsSize = strlen(CurrentModule) + 1;
			FormattedImports = new char[FormattedImportsSize] {};
			if (FormattedImports == nullptr)
			{
				RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
			}
			strcpy_s(FormattedImports, FormattedImportsSize, CurrentModule);
		}
		else
		{
			char* ResizedImports = nullptr;
			__try
			{
				size_t ResizedImportsSize = strlen(FormattedImports) + strlen(CurrentModule) + 2;
				ResizedImports = new char[ResizedImportsSize] {};
				if (ResizedImports == nullptr)
				{
					RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
				}
				strcpy_s(ResizedImports, ResizedImportsSize, FormattedImports);
				strcat_s(ResizedImports, ResizedImportsSize, "\n");
				strcat_s(ResizedImports, ResizedImportsSize, CurrentModule);
			}
			__finally
			{
				if (FormattedImports)
				{
					delete[] FormattedImports;
				}
			}
			FormattedImports = ResizedImports;
		}


		char* FormattedFunctionNames = nullptr;
		switch (dwArchitecture)
		{

		case IMAGE_FILE_MACHINE_AMD64:
		{
			const uint64_t* ImageLookupTable = reinterpret_cast<const uint64_t*>(reinterpret_cast<const BYTE*>(pMappedFile) + ConvertToFileOffset(pMappedFile, ImportsLoop->OriginalFirstThunk, dwArchitecture));
			for (; *ImageLookupTable != NULL; ImageLookupTable++)
			{
				if (*ImageLookupTable & 0x8000000000000000)
				{
					//Oridinal...
				}
				else
				{
					DWORD NameRelativeOffset = *ImageLookupTable;
					const _IMAGE_IMPORT_BY_NAME* NameTable = reinterpret_cast<const _IMAGE_IMPORT_BY_NAME*>(reinterpret_cast<const BYTE*>(pMappedFile) + ConvertToFileOffset(pMappedFile, NameRelativeOffset, dwArchitecture));

					if (FormattedFunctionNames == nullptr)
					{
						size_t FormattedFunctionNamesSize = strlen(NameTable->Name) + INDENT_AMOUNT + 1;
						FormattedFunctionNames = new char[FormattedFunctionNamesSize] {};
						if (FormattedFunctionNames == nullptr)
						{
							if (FormattedImports)
							{
								delete[] FormattedImports;
							}
							RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
						}
						strcpy_s(FormattedFunctionNames, FormattedFunctionNamesSize, "      ");
						strcat_s(FormattedFunctionNames, FormattedFunctionNamesSize, NameTable->Name);
					}
					else
					{
						size_t ResizedFunctionNamesSize = strlen(FormattedFunctionNames) + strlen(NameTable->Name) + INDENT_AMOUNT + 2;
						char* ResizedFunctionNames = new char[ResizedFunctionNamesSize] {};
						if (ResizedFunctionNames == nullptr)
						{
							if (FormattedImports)
							{
								delete[] FormattedImports;
							}
							if (FormattedFunctionNames)
							{
								delete[] FormattedFunctionNames;
							}
							RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
						}
						strcpy_s(ResizedFunctionNames, ResizedFunctionNamesSize, FormattedFunctionNames);
						strcat_s(ResizedFunctionNames, ResizedFunctionNamesSize, "\n");
						strcat_s(ResizedFunctionNames, ResizedFunctionNamesSize, "      ");
						strcat_s(ResizedFunctionNames, ResizedFunctionNamesSize, NameTable->Name);
						if (FormattedFunctionNames)
						{
							delete[] FormattedFunctionNames;
						}
						FormattedFunctionNames = ResizedFunctionNames;
					}
				}
			}

			char* ResizedFormattedImports = nullptr;
			__try
			{
				size_t FormattedImportsResizedSize = strlen(FormattedImports) + strlen(FormattedFunctionNames) + 3;
				ResizedFormattedImports = new char[FormattedImportsResizedSize];
				if (ResizedFormattedImports == nullptr)
				{
					RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
				}
				strcpy_s(ResizedFormattedImports, FormattedImportsResizedSize, FormattedImports);
				strcat_s(ResizedFormattedImports, FormattedImportsResizedSize, "\n");
				strcat_s(ResizedFormattedImports, FormattedImportsResizedSize, FormattedFunctionNames);
				strcat_s(ResizedFormattedImports, FormattedImportsResizedSize, "\n");
			}
			__finally
			{
				if (FormattedImports)
				{
					delete[] FormattedImports;
				}
				if (FormattedFunctionNames)
				{
					delete[] FormattedFunctionNames;
				}
			}
		
			FormattedImports = ResizedFormattedImports;
			break;
		}


		case IMAGE_FILE_MACHINE_I386:
		{
			const uint32_t* ImageLookupTable = reinterpret_cast<const uint32_t*>(reinterpret_cast<const BYTE*>(pMappedFile) + ConvertToFileOffset(pMappedFile, ImportsLoop->OriginalFirstThunk, dwArchitecture));
			for (; *ImageLookupTable != NULL; ImageLookupTable++)
			{
				if (*ImageLookupTable & 0x80000000)
				{
					//Oridinal...
				}
				else
				{
					DWORD NameRelativeOffset = *ImageLookupTable;
					const _IMAGE_IMPORT_BY_NAME* NameTable = reinterpret_cast<const _IMAGE_IMPORT_BY_NAME*>(reinterpret_cast<const BYTE*>(pMappedFile) + ConvertToFileOffset(pMappedFile, NameRelativeOffset, dwArchitecture));

					if (FormattedFunctionNames == nullptr)
					{
						size_t FormattedFunctionNamesSize = strlen(NameTable->Name) + INDENT_AMOUNT + 1;
						FormattedFunctionNames = new char[FormattedFunctionNamesSize] {};
						if (FormattedFunctionNames == nullptr)
						{
							if (FormattedImports)
							{
								delete[] FormattedImports;
							}
							RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
						}
						strcpy_s(FormattedFunctionNames, FormattedFunctionNamesSize, "      ");
						strcat_s(FormattedFunctionNames, FormattedFunctionNamesSize, NameTable->Name);
					}
					else
					{
						size_t ResizedFunctionNamesSize = strlen(FormattedFunctionNames) + strlen(NameTable->Name) + INDENT_AMOUNT + 2;
						char* ResizedFunctionNames = new char[ResizedFunctionNamesSize] {};
						if (ResizedFunctionNames == nullptr)
						{
							if (FormattedImports)
							{
								delete[] FormattedImports;
							}
							if (FormattedFunctionNames)
							{
								delete[] FormattedFunctionNames;
							}
							RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
						}
						strcpy_s(ResizedFunctionNames, ResizedFunctionNamesSize, FormattedFunctionNames);
						strcat_s(ResizedFunctionNames, ResizedFunctionNamesSize, "\n");
						strcat_s(ResizedFunctionNames, ResizedFunctionNamesSize, "      ");
						strcat_s(ResizedFunctionNames, ResizedFunctionNamesSize, NameTable->Name);
						if (FormattedFunctionNames)
						{
							delete[] FormattedFunctionNames;
						}
						FormattedFunctionNames = ResizedFunctionNames;
					}
				}
			}

			char* ResizedFormattedImports = nullptr;
			__try
			{
				size_t FormattedImportsResizedSize = strlen(FormattedImports) + strlen(FormattedFunctionNames) + 3;
				ResizedFormattedImports = new char[FormattedImportsResizedSize];
				if (ResizedFormattedImports == nullptr)
				{
					RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
				}
				strcpy_s(ResizedFormattedImports, FormattedImportsResizedSize, FormattedImports);
				strcat_s(ResizedFormattedImports, FormattedImportsResizedSize, "\n");
				strcat_s(ResizedFormattedImports, FormattedImportsResizedSize, FormattedFunctionNames);
				strcat_s(ResizedFormattedImports, FormattedImportsResizedSize, "\n");
			}
			__finally
			{
				if (FormattedImports)
				{
					delete[] FormattedImports;
				}
				if (FormattedFunctionNames)
				{
					delete[] FormattedFunctionNames;
				}
			}

			FormattedImports = ResizedFormattedImports;
			break;
		}

		}

	}

#ifdef UNICODE
	size_t WideImportsSize = MultiByteToWideChar(CP_UTF8, NULL, FormattedImports, -1, nullptr, NULL);
	if (!WideImportsSize)
	{
		return nullptr;
	}
	WCHAR* WideImports = new WCHAR[WideImportsSize]{};
	if (WideImports == nullptr)
	{
		RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
	}
	MultiByteToWideChar(CP_UTF8, NULL, FormattedImports, -1, WideImports, WideImportsSize);
	if (FormattedImports)
	{
		delete[] FormattedImports;
	}
	return WideImports;
#else
	return FormattedImports;
#endif
}



TCHAR* ParseExports(const void* pMappedFile, Request* pCurrentRequest, DWORD dwArchitecture)
{
	const	IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(pMappedFile);
	const	IMAGE_EXPORT_DIRECTORY* Exports = nullptr;



	switch (dwArchitecture)
	{

	case IMAGE_FILE_MACHINE_AMD64:
	{
		const IMAGE_NT_HEADERS64* NtHeader = reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const BYTE*>(pMappedFile) + DosHeader->e_lfanew);
		IMAGE_DATA_DIRECTORY ImageDataDirectory = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!ImageDataDirectory.Size)
		{
			return nullptr;
		}
		Exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(reinterpret_cast<const BYTE*>(pMappedFile) + ConvertToFileOffset(pMappedFile, ImageDataDirectory.VirtualAddress, dwArchitecture));
		break;
	}

	case IMAGE_FILE_MACHINE_I386:
	{
		const IMAGE_NT_HEADERS32* NtHeader = reinterpret_cast<const IMAGE_NT_HEADERS32*>(reinterpret_cast<const BYTE*>(pMappedFile) + DosHeader->e_lfanew);
		IMAGE_DATA_DIRECTORY ImageDataDirectory = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!ImageDataDirectory.Size)
		{
			return nullptr;
		}
		Exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(reinterpret_cast<const BYTE*>(pMappedFile) + ConvertToFileOffset(pMappedFile, ImageDataDirectory.VirtualAddress, dwArchitecture));
		break;
	}

	default:
	{
		RaiseException(QUERI_EXCEPTION_INVALID_ARCHITECTURE, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
	}

	}

	if (!Exports->AddressOfNames)
	{
		return nullptr;
	}

	char* FormattedExports = nullptr;
	const DWORD* NameArray = reinterpret_cast<const DWORD*>(reinterpret_cast<const BYTE*>(pMappedFile) + ConvertToFileOffset(pMappedFile, Exports->AddressOfNames, dwArchitecture));
	for (DWORD i = 0; i < Exports->NumberOfNames; i++)
	{
		const char* CurName = reinterpret_cast<const char*>(reinterpret_cast<const BYTE*>(pMappedFile) + ConvertToFileOffset(pMappedFile, NameArray[i], dwArchitecture));

		if (FormattedExports == nullptr)
		{
			FormattedExports = new char[strlen(CurName) + 2]{};
			if (FormattedExports == nullptr)
			{
				RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
			}
			strcpy_s(FormattedExports, strlen(CurName) + 2, CurName);
			strcat_s(FormattedExports, strlen(CurName) + 2, "\n");
		}
		else
		{
			size_t ResizedNameBufferSize = strlen(FormattedExports) + strlen(CurName) + 2;
			char* ResizedNameBuffer = new char[ResizedNameBufferSize] {};
			if (ResizedNameBuffer == nullptr)
			{
				if (FormattedExports)
				{
					delete[] FormattedExports;
				}
				RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
			}
			strcpy_s(ResizedNameBuffer, ResizedNameBufferSize, FormattedExports);
			strcat_s(ResizedNameBuffer, ResizedNameBufferSize, CurName);
			strcat_s(ResizedNameBuffer, ResizedNameBufferSize, "\n");
			if (FormattedExports)
			{
				delete[] FormattedExports;
			}
			FormattedExports = ResizedNameBuffer;
		}
	}
	
	
#ifdef UNICODE
	size_t WideImportsSize = MultiByteToWideChar(CP_UTF8, NULL, FormattedExports, -1, nullptr, NULL);
	if (!WideImportsSize)
	{
		return nullptr;
	}
	WCHAR* WideImports = new WCHAR[WideImportsSize]{};
	if (WideImports == nullptr)
	{
		RaiseException(QUERI_EXCEPTION_MEMORY_ALLOC_FAILED, EXCEPTION_NONCONTINUABLE, NULL, nullptr);
	}
	MultiByteToWideChar(CP_UTF8, NULL, FormattedExports, -1, WideImports, WideImportsSize);
	if (FormattedExports)
	{
		delete[] FormattedExports;
	}
	return WideImports;
#else
	return FormattedImports;
#endif
}
