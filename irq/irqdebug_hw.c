#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/hw_breakpoint.h>

#include "debug_log.h"
#include "debug_utils.h"

#define IRQ_DEBUG_HWBREAKPOINT_ROOT_DIR "irqhw_breakpoints"

static ssize_t affinity_hint_write(struct file *fp, const char __user *buf,
                                   size_t count, loff_t *ppos)
{
    char irq_str[64] = {0};
    int32_t ret = 0, enable = 0;
    int32_t len = simple_write_to_buffer(irq_str, sizeof(irq_str), ppos, buf, count);

    char *p = strchr(irq_str, '\r');
    if (p)
    {
        *p = '\0';
    }
    p = strchr(irq_str, '\n');
    if (p)
    {
        *p = '\0';
    }
    p = strchr(irq_str, ' ');
    if (p)
    {
        *p = '\0';
    }

    if (!strcmp(irq_str, "on"))
    {
        enable = 1;
    }
    else if (!strcmp(irq_str, "off"))
    {
        enable = 0;
    }
    else
    {
        len = -EINVAL;
    }

    return len;
}

static const struct file_operations affinity_hint_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .write = affinity_hint_write,
    .llseek = default_llseek,
};

static debugfs_file_init_t irq_hw_breakpoints_debugsf_files[] = {
    // INIT_DEBUGFS_FILE_CREATE(export_irqdesc, NULL, 0666),
    // INIT_DEBUGFS_FILE_CREATE(irqdesc_info, NULL, 0444),
    // INIT_DEBUGFS_FILE_CREATE(affinity_hint, NULL, 0222),
};

int32_t debug_irq_hw_breakpoint_init(struct dentry *irq_root_dir)
{
    return debug_utils_common_init(irq_root_dir, IRQ_DEBUG_HWBREAKPOINT_ROOT_DIR,
                                   irq_hw_breakpoints_debugsf_files, ARRAY_SIZE(irq_hw_breakpoints_debugsf_files));
}
