#ifndef __DEBUG_LOG_HHHH
#define __DEBUG_LOG_HHHH

#include <linux/printk.h>

#undef pr_fmt
#define pr_fmt(fmt) "[%s(): %u] - " fmt, __func__, __LINE__

#endif
