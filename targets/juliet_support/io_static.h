/* Juliet C/C++ v1.3 testcasesupport/io.c helpers, made static so only the ones a
 * target calls end up in its binary. good1()..bad9() dummies dropped. */
#ifndef _IO_STATIC_H
#define _IO_STATIC_H
#include <inttypes.h> // for PRId64
#include <stdio.h>
#include <stdlib.h>
#include <wctype.h>


#ifndef _WIN32
#include <wchar.h>
#endif
static inline void printLine (const char * line)
{
    if(line != NULL) 
    {
        printf("%s\n", line);
    }
}
static inline void printWLine (const wchar_t * line)
{
    if(line != NULL) 
    {
        wprintf(L"%ls\n", line);
    }
}
static inline void printIntLine (int intNumber)
{
    printf("%d\n", intNumber);
}
static inline void printShortLine (short shortNumber)
{
    printf("%hd\n", shortNumber);
}
static inline void printFloatLine (float floatNumber)
{
    printf("%f\n", floatNumber);
}
static inline void printLongLine (long longNumber)
{
    printf("%ld\n", longNumber);
}
static inline void printLongLongLine (int64_t longLongIntNumber)
{
    printf("%" PRId64 "\n", longLongIntNumber);
}
static inline void printSizeTLine (size_t sizeTNumber)
{
    printf("%zu\n", sizeTNumber);
}
static inline void printHexCharLine (char charHex)
{
    printf("%02x\n", charHex);
}
static inline void printWcharLine(wchar_t wideChar) 
{
    /* ISO standard dictates wchar_t can be ref'd only with %ls, so we must make a
     * string to print a wchar */
    wchar_t s[2];
        s[0] = wideChar;
        s[1] = L'\0';
    printf("%ls\n", s);
}
static inline void printUnsignedLine(unsigned unsignedNumber) 
{
    printf("%u\n", unsignedNumber);
}
static inline void printHexUnsignedCharLine(unsigned char unsignedCharacter) 
{
    printf("%02x\n", unsignedCharacter);
}
static inline void printDoubleLine(double doubleNumber) 
{
    printf("%g\n", doubleNumber);
}
static inline void printStructLine (const twoIntsStruct * structTwoIntsStruct)
{
    printf("%d -- %d\n", structTwoIntsStruct->intOne, structTwoIntsStruct->intTwo);
}
static inline void printBytesLine(const unsigned char * bytes, size_t numBytes)
{
    size_t i;
    for (i = 0; i < numBytes; ++i)
    {
        printf("%02x", bytes[i]);
    }
    puts("");	/* output newline */
}

/* Decode a string of hex characters into the bytes they represent.  The second
 * parameter specifies the length of the output buffer.  The number of bytes
 * actually written to the output buffer is returned. */
static inline size_t decodeHexChars(unsigned char * bytes, size_t numBytes, const char * hex)
{
    size_t numWritten = 0;

    /* We can't sscanf directly into the byte array since %02x expects a pointer to int,
     * not a pointer to unsigned char.  Also, since we expect an unbroken string of hex
     * characters, we check for that before calling sscanf; otherwise we would get a
     * framing error if there's whitespace in the input string. */
    while (numWritten < numBytes && isxdigit(hex[2 * numWritten]) && isxdigit(hex[2 * numWritten + 1]))
    {
        int byte;
        sscanf(&hex[2 * numWritten], "%02x", &byte);
        bytes[numWritten] = (unsigned char) byte;
        ++numWritten;
    }

    return numWritten;
}

/* Decode a string of hex characters into the bytes they represent.  The second
 * parameter specifies the length of the output buffer.  The number of bytes
 * actually written to the output buffer is returned. */
static inline size_t decodeHexWChars(unsigned char * bytes, size_t numBytes, const wchar_t * hex)
 {
    size_t numWritten = 0;

    /* We can't swscanf directly into the byte array since %02x expects a pointer to int,
     * not a pointer to unsigned char.  Also, since we expect an unbroken string of hex
     * characters, we check for that before calling swscanf; otherwise we would get a
     * framing error if there's whitespace in the input string. */
    while (numWritten < numBytes && iswxdigit(hex[2 * numWritten]) && iswxdigit(hex[2 * numWritten + 1]))
    {
        int byte;
        swscanf(&hex[2 * numWritten], L"%02x", &byte);
        bytes[numWritten] = (unsigned char) byte;
        ++numWritten;
    }

    return numWritten;
}

/* The two functions always return 1 or 0, so a tool should be able to 
   identify that uses of these functions will always return these values */
static inline int globalReturnsTrue() 
{
    return 1;
}
static inline int globalReturnsFalse() 
{
    return 0;
}
static inline int globalReturnsTrueOrFalse() 
{
    return (rand() % 2);
}

/* The variables below are declared "const", so a tool should
   be able to identify that reads of these will always return their 
   initialized values. */
static const int GLOBAL_CONST_TRUE = 1; /* true */
static const int GLOBAL_CONST_FALSE = 0; /* false */
static const int GLOBAL_CONST_FIVE = 5; 

/* The variables below are not defined as "const", but are never
   assigned any other value, so a tool should be able to identify that
   reads of these will always return their initialized values. */
static int globalTrue = 1; /* true */
static int globalFalse = 0; /* false */
static int globalFive = 5; 


#endif
