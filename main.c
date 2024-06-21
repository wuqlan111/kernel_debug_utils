#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/debugfs.h>

#include "debug_log.h"

#define DEBUG_UTILS_ROOT_DIR "debug_utils"

static struct dentry *debug_utils_root_dir = NULL;

static int32_t __init debug_utils_init(void)
{
    int32_t ret = 0;
    pr_info("start debug utils init\n");

    debug_utils_root_dir = debugfs_create_dir(DEBUG_UTILS_ROOT_DIR, NULL);

    if (!debug_utils_root_dir)
    {
        pr_err("ebug utils init failed!\n");
        ret = -EINVAL;
    }
    else
    {
        pr_info("debug utils init successful\n");
    }

    return ret;
}

static void __exit debug_utils_exit(void)
{
    pr_info("debug utils exit\n");
    if (debug_utils_root_dir)
    {
        debugfs_remove_recursive(debug_utils_root_dir);
    }
}

module_init(debug_utils_init);
module_exit(debug_utils_exit);

MODULE_AUTHOR("wuqlan111");
MODULE_DESCRIPTION("linux kernel debug utils");
MODULE_LICENSE("GPL v2");
