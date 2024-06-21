#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/irqflags.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/err.h>
#include <linux/uaccess.h>

#include "debug_log.h"

#define IRQDESC_DEBUG_ROOT_DIR "irqdesc"
#define INVALID_IRQ_NUMBER (-1)

static int32_t export_irq = 0;
static inline void set_export_irq(int32_t irq)
{
    export_irq = irq;
}

static inline int32_t get_export_irq(void)
{
    return export_irq;
}

static ssize_t export_irqdesc_read(struct file *fp, char __user *buf,
                                   size_t count, loff_t *ppos)
{
    char tmp_str[32] = {0};
    int32_t len = sprintf(tmp_str, "%d", get_export_irq());
    copy_to_user(buf, tmp_str, len);

    pr_debug("exported irq [%d]\n", get_export_irq());

    return simple_read_from_buffer(tmp_str, count, ppos,
                                   buf, len);
}

static ssize_t export_irqdesc_write(struct file *fp, const char __user *buf,
                                    size_t count, loff_t *ppos)
{
    char *irq_str = strndup_user(buf, 32);
    int32_t len = 0, tmp_irq = 0;
    if (IS_ERR_OR_NULL(irq_str))
    {
        pr_err("get user irq number failed\n");
        return -EPERM;
    }

    long res = 0;
    len = kstrtol(irq_str, 10, &res);
    tmp_irq = res;
    if (len || (tmp_irq < 0))
    {
        len = -EPERM;
        tmp_irq = INVALID_IRQ_NUMBER;
        pr_err("user irq [%s] invalid\n", irq_str);
        goto end;
    }

    if (!irq_to_desc(tmp_irq))
    {
        tmp_irq = INVALID_IRQ_NUMBER;
        len = -EINVAL;
        pr_err("irq [%d] doesn't exist\n", tmp_irq);
    }
    else
    {
        len = strlen(irq_str);
    }

end:
    kfree(irq_str);
    set_export_irq(tmp_irq);

    // if (len > 0) {
    //     *pops = fp->f_pos +=
    // }

    return len;
}

static const struct file_operations export_irqdesc_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = export_irqdesc_read,
    .write = export_irqdesc_write,
    .llseek = default_llseek,
};

static debugfs_file_init_t irqdesc_debugsf_files[] = {
    INIT_DEBUGFS_FILE_CREATE(export_irqdesc, NULL, 0644),
};

int32_t debug_irqdesc_init(struct dentry *irq_root_dir)
{
    int32_t ret = 0;
    if (!irq_root_dir)
    {
        return -EPERM;
    }

    struct dentry *dir = debugfs_create_dir(IRQDESC_DEBUG_ROOT_DIR, irq_root_dir);
    if (!dir)
    {
        pr_err("init irqdesc debug failed!\n");
        return -EINVAL;
    }

    for (int32_t i = 0; i < ARRAY_SIZE(irqdesc_debugsf_files); ++i)
    {
        if (!debugfs_create_file(irqdesc_debugsf_files[i].name, irqdesc_debugsf_files[i].mode,
                                 dir, irqdesc_debugsf_files[i].data, irqdesc_debugsf_files[i].fops))
        {
            ret = -EINVAL;
            pr_err("create " IRQDESC_DEBUG_ROOT_DIR "/%s failed",
                   irqdesc_debugsf_files[i].name);
            break;
        }
    }

    return ret;
}
