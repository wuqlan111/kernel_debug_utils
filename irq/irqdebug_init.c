#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/debugfs.h>

#include "debug_log.h"

#define IRQ_DEBUG_ROOT_DIR "irq_debug"

extern int32_t debug_irqdesc_init(struct dentry *irq_root_dir);
extern int32_t debug_irqdomain_init(struct dentry *irq_root_dir);

int32_t irq_debug_init(struct dentry *root_dir)
{
    int32_t ret = 0;
    if (!root_dir)
    {
        return -EPERM;
    }

    struct dentry *dir = debugfs_create_dir(IRQ_DEBUG_ROOT_DIR, root_dir);

    if (!dir)
    {
        ret = -EINVAL;
        pr_err("init irqdesc debug failed!\n");
        goto end;
    }

    ret = debug_irqdesc_init(dir);
    ret |= debug_irqdomain_init(dir);

end:
    return ret;
}
