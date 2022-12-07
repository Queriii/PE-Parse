#pragma once

//Startup exceptions
#define QUERI_EXCEPTION_INVALID_STARTUP_ARGS		0xE0000001
#define QUERI_EXCEPTION_STARTUP_ARG_PATH_TOO_LONG	0xE0000002

//File sys exceptions
#define QUERI_EXCEPTION_INVALID_FILE_HANDLE			0xE0000003
#define QUERI_EXCEPTION_MAP_FILE					0xE0000004
#define QUERI_EXCEPTION_MAP_FILE_VIEW				0xE0000005

//Thread exceptions
#define QUERI_EXCEPTION_CREATE_THREAD				0xE0000006

//User interactino exceptions
#define QUERI_EXCEPTION_UNKNOWN_REQUEST				0xE0000007
#define QUERI_EXCEPTION_INVALID_FILE				0xE0000008
#define QUERI_EXCEPTION_INVALID_ARCHITECTURE		0xE0000009
#define QUERI_EXCEPTION_INVALID_ARGS				0xE000000B
#define QUERI_EXCEPTION_NO_ARGS_PROVIDED			0xE000000E
#define QUERI_EXCEPTION_DOES_NOT_CONTAIN_OPT_HDR	0xE000000C

//Memory exceptions
#define QUERI_EXCEPTION_MEMORY_ALLOC_FAILED			0xE000000A
#define QUERI_EXCEPTION_BUFFER_SIZE_DETERM_FAILED	0xE000000D