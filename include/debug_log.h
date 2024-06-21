#ifndef __DEBUG_LOG_HHHH
#define __DEBUG_LOG_HHHH

#include <linux/printk.h>
#include <linux/debugfs.h>

#undef pr_fmt
#define pr_fmt(fmt) "[%s(): %u] - " fmt, __func__, __LINE__

typedef struct
{
    char *name;
    void *data;
    umode_t mode;
    const struct file_operations *fops;
} debugfs_file_init_t;

#define INIT_DEBUGFS_FILE_CREATE(nm, dt, md) \
    {                                              \
        .name = #nm,                             \
        .data = (dt),                              \
        .mode = (md),                              \
        .fops = &nm##_fops,                       \
    }

#endif
