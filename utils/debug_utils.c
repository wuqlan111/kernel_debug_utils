#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/debugfs.h>

#include "debug_log.h"
#include "debug_utils.h"

int32_t debug_utils_common_init(struct dentry *root_dir, const char *sub_dir,
                                const debugfs_file_init_t *init_files, const int32_t size)
{
    int32_t ret = 0;
    if (!root_dir || !sub_dir || (!init_files && size) || (size < 0))
    {
        return -EPERM;
    }

    struct dentry *dir = debugfs_create_dir(sub_dir, root_dir);
    if (!dir)
    {
        pr_err("init %s failed!\n", sub_dir);
        return -EINVAL;
    }

    for (int32_t i = 0; i < size; ++i)
    {
        if (!debugfs_create_file(init_files[i].name, init_files[i].mode,
                                 dir, init_files[i].data, init_files[i].fops))
        {
            ret = -EINVAL;
            pr_err("create %s/%s failed", sub_dir, init_files[i].name);
            break;
        }
    }

    return ret;
}
