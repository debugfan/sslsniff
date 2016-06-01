#ifndef TYPE_DEF_H
#define TYPE_DEF_H

typedef signed char       int8_t;
typedef signed short      int16_t;
typedef signed int        int32_t;
typedef unsigned char     uint8_t;
typedef unsigned short    uint16_t;
typedef unsigned int      uint32_t;

typedef unsigned char     u_int8_t;
typedef unsigned short    u_int16_t;
typedef unsigned int      u_int32_t;


typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned char u_char;
//typedef unsigned long u_long;

typedef unsigned long       DWORD;
//typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef float               FLOAT;
typedef FLOAT               *PFLOAT;

#if 0
typedef BOOL near           *PBOOL;
typedef BOOL far            *LPBOOL;
typedef BYTE near           *PBYTE;
typedef BYTE far            *LPBYTE;
typedef int near            *PINT;
typedef int far             *LPINT;
typedef WORD near           *PWORD;
typedef WORD far            *LPWORD;
typedef long far            *LPLONG;
typedef DWORD near          *PDWORD;
typedef DWORD far           *LPDWORD;
typedef void far            *LPVOID;
typedef CONST void far      *LPCVOID;
#endif

typedef int                 INT;
typedef unsigned int        UINT;
typedef unsigned int        *PUINT;

#endif
