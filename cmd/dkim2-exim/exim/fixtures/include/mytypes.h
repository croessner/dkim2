#ifndef MYTYPES_H
#define MYTYPES_H

#include <string.h>

#define FALSE 0
#define TRUE 1
#define TRUE_UNSET 2

#if defined(__GNUC__) || defined(__clang__)
#define ARG_UNUSED __attribute__((__unused__))
#define FUNC_MAYBE_UNUSED __attribute__((__unused__))
#define WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#define ALLOC __attribute__((malloc))
#define NORETURN __attribute__((noreturn))
#define ALLOC_SIZE(A) __attribute__((alloc_size(A)))
#else
#define ARG_UNUSED
#define FUNC_MAYBE_UNUSED
#define WARN_UNUSED_RESULT
#define ALLOC
#define NORETURN
#define ALLOC_SIZE(A)
#endif

#define PRINTF_FUNCTION(A, B)
#define ALMOST_PRINTF(A, B)

typedef unsigned char uschar;
typedef unsigned BOOL;

#define CS (char *)
#define CCS (const char *)
#define CSS (char **)
#define US (unsigned char *)
#define CUS (const unsigned char *)
#define USS (unsigned char **)
#define CUSS (const unsigned char **)
#define CCSS (const char **)

#endif
