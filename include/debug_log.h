#ifndef __DEBUG_LOG_HHHH
#define __DEBUG_LOG_HHHH

#include <linux/printk.h>
#include <linux/debugfs.h>

#undef pr_fmt
#define pr_fmt(fmt) "[%s(): %u] - " fmt, __func__, __LINE__

#define TYPE_CASE(x) \
    case (x):        \
        return #x;

#define STRING_OR_NULL(str) ((str) ? (str) : "null")

typedef struct
{
    char *name;
    void *data;
    umode_t mode;
    const struct file_operations *fops;
} debugfs_file_init_t;

#define INIT_DEBUGFS_FILE_CREATE(nm, dt, md) \
    {                                        \
        .name = #nm,                         \
        .data = (dt),                        \
        .mode = (md),                        \
        .fops = &nm##_fops,                  \
    }

typedef struct
{
    unsigned long mask;
    const char *name;
} bit_mask_descr_t;

#define BIT_MASK_DESCR(m)     \
    {                         \
        .mask = m, .name = #m \
    }

#endif
