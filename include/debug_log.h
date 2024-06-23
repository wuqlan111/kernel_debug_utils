#ifndef __DEBUG_LOG_HHHH
#define __DEBUG_LOG_HHHH

#include <linux/printk.h>

#undef pr_fmt
#define pr_fmt(fmt) "[%s(): %u] - " fmt, __func__, __LINE__

#define TYPE_CASE(x) \
        case (x):    \
                return #x;

#define STRING_OR_NULL(str) ((str) ? (str) : "null")

#define UINT_TO_POINTER(x) ((void *)((uintptr_t)(x)))

#if 0
#define UINT_TO_POINTER(x) ({\
        uintptr_t tmp_int = (x); \
        void * ptr = (void *)tmp_int;\
        ptr; })
#endif

#endif
