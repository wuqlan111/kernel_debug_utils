#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/debugfs.h>

#include "debug_log.h"

#define IRQDESC_DEBUG_ROOT_DIR "irqdesc"

int32_t  debug_irqdesc_init(struct dentry *irq_root_dir)
{
    int32_t ret = 0;
    if (!irq_root_dir)
    {
        return -EPERM;
    }

    struct dentry *dir = debugfs_create_dir(IRQDESC_DEBUG_ROOT_DIR, irq_root_dir);

    if (!dir)
    {
        ret = -EINVAL;
        pr_err("init irqdesc debug failed!\n");
    }

    return ret;
}
