#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/debugfs.h>

#include "debug_log.h"

#define FS_DEBUG_ROOT_DIR "fs_debug"

extern int32_t debug_file_info_init(struct dentry *irq_root_dir);

int32_t fs_debug_init(struct dentry *root_dir)
{
    int32_t ret = 0;
    if (!root_dir)
    {
        return -EPERM;
    }

    struct dentry *dir = debugfs_create_dir(FS_DEBUG_ROOT_DIR, root_dir);

    if (!dir)
    {
        ret = -EINVAL;
        pr_err("init fs debug failed!\n");
        goto end;
    }

    ret = debug_file_info_init(dir);

end:
    return ret;
}
