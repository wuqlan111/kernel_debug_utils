#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/fs.h>

#include "debug_log.h"
#include "debug_utils.h"

#define FILE_INFO_ROOT_DIR "file_info"

static struct filename *export_file_name = NULL;

static inline void set_export_file_name(void *filename)
{
    export_file_name = filename;
}

static inline struct filename *get_export_file_name(void)
{
    return export_file_name;
}

static ssize_t export_filename_read(struct file *fp, char __user *buf,
                                    size_t count, loff_t *ppos)
{

    struct filename *filename = get_export_file_name();
    if (!filename)
    {
        return -EINVAL;
    }

    return simple_read_from_buffer(buf, count, ppos, STRING_OR_NULL(filename->name),
                                   strlen(STRING_OR_NULL(filename->name)));
}

typedef struct filename *(*getname_func_t)(const char __user *);
typedef void (*putname_func_t)(struct filename *name);

static ssize_t export_filename_write(struct file *fp, const char __user *buf,
                                     size_t count, loff_t *ppos)
{
    char irq_str[1024] = {0};
    int32_t len = simple_write_to_buffer(irq_str, sizeof(irq_str), ppos, buf, count);

    getname_func_t getname_func = NULL;
    putname_func_t putname_func = NULL;
    getname_func = debug_utils_get_kernel_symbol("getname");
    putname_func = debug_utils_get_kernel_symbol("putname");
    if (!getname_func || !putname_func)
    {
        pr_err("get filename func symbol failed!\n");
        return -EINVAL;
    }

    struct filename *ori = NULL;
    struct filename *file = getname_func(buf);
    if (!file)
    {
        len = -EPERM;
    }
    else
    {
        ori = get_export_file_name();
        set_export_file_name(file);
    }

    if (ori)
    {
        putname_func(ori);
    }

    return len;
}

static const struct file_operations export_filename_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = export_filename_read,
    .write = export_filename_write,
    .llseek = default_llseek,
};

static debugfs_file_init_t file_info_files[] = {
    INIT_DEBUGFS_FILE_CREATE(export_filename, NULL, 0666),
    // INIT_DEBUGFS_FILE_CREATE(export_irqdomain, NULL, 0666),
    // INIT_DEBUGFS_FILE_CREATE(irqdomain_info, NULL, 0444),
    // INIT_DEBUGFS_FILE_CREATE(default_irqdomain, NULL, 0444),
    // INIT_DEBUGFS_FILE_CREATE(existed_irqdomain, NULL, 0444),
};

int32_t debug_file_info_init(struct dentry *irq_root_dir)
{
    return debug_utils_common_init(irq_root_dir, FILE_INFO_ROOT_DIR,
                                   file_info_files, ARRAY_SIZE(file_info_files));
}
