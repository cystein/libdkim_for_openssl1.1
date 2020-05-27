/*
 * macros.h:  Useful macros
 *
 * Author:
 *	Dick Porter (dick@ximian.com)
 *
 * (C) 2002 Ximian, Inc.
 */

#ifndef _WAPI_MACROS_H_
#define _WAPI_MACROS_H_

#include <sys/types.h>

#define MAKEWORD(low, high) ((__uint16_t)(((__uint8_t)(low)) | \
				       ((__uint16_t)((__uint8_t)(high))) << 8))
#define MAKELONG(low, high) ((__uint32_t)(((__uint16_t)(low)) | \
				       ((__uint32_t)((__uint16_t)(high))) << 16))
#define LOWORD(i32) ((__uint16_t)((i32) & 0xFFFF))
#define HIWORD(i32) ((__uint16_t)(((__uint32_t)(i32) >> 16) & 0xFFFF))
#define LOBYTE(i16) ((__uint8_t)((i16) & 0xFF))
#define HIBYTE(i16) ((__uint8_t)(((__uint16_t)(i16) >> 8) & 0xFF))

#endif /* _WAPI_MACROS_H_ */
