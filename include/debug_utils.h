#ifndef __DEBUG_UTILS_HHHH
#define __DEBUG_UTILS_HHHH

#include <linux/printk.h>
#include <linux/debugfs.h>

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

int32_t debug_utils_common_init(struct dentry *root_dir, const char *sub_dir,
                                const debugfs_file_init_t *init_files, const int32_t size);

void *debug_utils_get_kernel_symbol(const char *sym);

int32_t get_cmd_args_from_string(char *str, char ***out, uint32_t *size);

void remove_string_line_break(char *str);

#endif
