#include "defines.h"
#include "functions.h"


/*
 * writes n bytes of src to dst
 * 
 * void *dst: the address to write to
 * const void *src: the address to read from
 * int n: the number of bytes to read/write
 * 
 * returns: starting address of overwritten memory
 */
void *mcpy(void *dst, const void *src, int n)
{
    char
        *pd = (char *)dst,
        *ps = (char *)src;

    while (n-- && (*pd++ = *ps++))
        ; // While there are still bytes to write and pd and ps are valid pointers, write the value at ps to pd

    return dst;
}

/*
 * calculates the length of a null-terminated string 
 * 
 * char *src: a null-terminated string
 * 
 * returns: the length of the string including the null byte
 */
unsigned int slen(char *src)
{
    unsigned int n = 0;

    while (*src != '\0' && *(src++) != '\r') // While the value at src isn't a null-byte or new-line, check the next address and count
        n++;

    return n;
}

/*
 * writes string src to dst
 * 
 * char *dst: the address to write to
 * const char* src: the address of the null-terminated string to read from
 * 
 * returns: the address of dst (now containing src)
 */
char *scpy(char *dst, const char *src)
{
    // int n = slen(dst); If we were smart, we would practice memory safety by calculating the length of the buffer before writing to it. I'm not though.

    char *p = dst;

    while ((*p++ = *src++)) //&& n--) and here we would break out of the loop before seg faulting
        ;

    *p = '\0'; // Append a null byte because we are returning a string

    return dst;
}

/*
 * reverses a null-terminated string
 * 
 * char *str: the address of a null-terminated string
 * 
 * returns: starting address of the buffer
 */
char *srev(char *str)
{
    char *end = str + slen(str) - 1; // Save the address at the end of the string (before null byte)

    while (str < end) // While the address of str is less than the address of end
    {
        *str ^= *end;         // XOR the value at the address of end with the value at the address of str and write the result to str
        *end ^= *str;         // XOR the value at the address of str with the value at the address of end and write the result to end
        *(str++) ^= *(end--); // XOR the value at the address of end with the value at the address of str, write the result to str, increment the address of str and decrement the address of end
    }

    return end;
}

/*
 * concatenates two null-terminated strings together
 * 
 * char *dst: the address of a null-terminated string to be written to
 * const char *src: the address of a null-terminated string to read from
 * 
 * returns: the address of dst (now containing dst + src)
 */
char *scat(char *dst, const char *src)
{
    char *ret = dst; // Save the starting address of dst

    while (*dst) // Increment the address of dst to the null byte
        dst++;

    while (*dst++ = *src++) // Write the value at the address of src to the address of dst and increment both addresses
        ;

    return ret; // Return the starting address that was saved
}

/*
 * compares two null-terminated strings
 * 
 * const char *s1: the address of a null-terminated string to read from
 * const char *s2: the address of a null-terminated string to read from
 * 
 * returns: 0 if s1 == s2 else the ASCII difference between them
 */
int scmp(char *s1, const char *s2)
{
    while (*s1)
        if (*s1++ != *s2++)
            break;

    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

/*
 * converts a number to its ASCII representation
 * 
 * int n: the number to be converted
 * int base: the base of n
 * 
 * returns: a null-terminated string of ASCII characters representing n
 */
char *ntos(int n, int base) // Num to string because itoa isn't allowed >:|
{
    if(n == 0) return "0"; // This is needed or else the timestamp will break at the top of each hour

    char ret[sizeof(n) + 1]; // If n is negative, need room for '-'

    int i = 0;

    if (n < 0 && base == 10) // Number is negative
    {
        n = -n;
        ret[i++] = '-';
    }

    while (n != 0) // While there is still number left
    {
        ret[i++] = (n % base > 9) ? (n % base - 10) + 'a' : n % base + '0'; // If the remainder of n/base has more than one digit, write the letter to ret, else write the number
        n /= base;                                                          // Save the next char at the next digit
    }

    ret[i] = '\0'; // Append a null byte to the string

    char *p = ret;
    srev(p); // The string is complete, but backwards, so reverse it

    return p;
}

/*
 * converts a string to its base 10 integer representation
 * 
 * char *str: a null-terminated string
 * 
 * returns: base 10 integer representation of str
 */
int ston(char *str)
{
    int ret = 0;

    for (int i = 0; str[i] != '\n' && str[i] != '\0'; ++i)
        ret = ret * 10 + str[i] - '0';

    return ret;
}

/*
 * XOR encrypts/decrypts n bytes starting at dst
 * 
 * void *dst: buffer to encrypt
 * int n: how many bytes to encrypt starting from dst
 */
void *cipher(void *dst, int n)
{
    char *pd = (char *)dst;

    while (n-- && *pd != (*pd++ ^= XOR)) // While there are still bytes to cipher and writing to pd is successful, XOR, write, and increment pd
        ;
}