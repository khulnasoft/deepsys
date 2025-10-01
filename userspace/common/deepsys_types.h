#ifdef _WIN32
#include <inttypes_win.h>
#ifndef __cplusplus
#define	bool int
#define false 0
#define true (!false)
#define inline inline
#endif /* __cplusplus */
#define snprintf _snprintf
#else
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdbool.h>
#endif /* _WIN32 */

//
// Import/typedef in userspace the kernel types
//
#if defined(__linux__)
#include <linux/types.h>
#else 
typedef uint64_t __u64;
typedef int64_t __s64;
typedef uint32_t __u32;
typedef int32_t __s32;
typedef uint16_t __u16;
typedef int16_t __s16;
typedef uint8_t __u8;
typedef int8_t __s8;
#endif
