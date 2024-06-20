#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include "debug_log.h"

static int32_t __init debug_utils_init(void)
{
    int32_t ret = 0;
    pr_info("debug utils init\n");

    return ret;
}

static void __exit debug_utils_exit(void)
{
    pr_info("debug utils exit\n");
}

module_init(debug_utils_init);
module_exit(debug_utils_exit);

MODULE_AUTHOR("wuqlan111");
MODULE_DESCRIPTION("linux kernel debug utils");
MODULE_LICENSE("GPL v2");
