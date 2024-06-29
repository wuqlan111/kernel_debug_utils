#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/kallsyms.h>
#include <linux/err.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>

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

#ifdef CONFIG_KALLSYMS
typedef unsigned long (*kallsyms_lookup_name_func_t)(const char *);

void *debug_utils_get_kernel_symbol(const char *sym)
{
    kallsyms_lookup_name_func_t get_sym_func = UINT_TO_POINTER(0xffff8000101830b0);
    if (!sym)
    {
        return NULL;
    }

    return UINT_TO_POINTER(get_sym_func(sym));
}

#else

void *debug_utils_get_kernel_symbol(const char *sym)
{
    return NULL;
}

#endif

int32_t get_cmd_args_from_string(char *str, char ***out, uint32_t *size)
{
    if (!str || !size || !out)
    {
        return -EPERM;
    }

    uint32_t argc = 0;

    *out = NULL;
    *size = 0;
    char *tmp = str;
    for (;;)
    {
        if (*tmp == '\0')
        {
            break;
        }

        if (*tmp == ' ')
        {
            tmp = skip_spaces(tmp);
        }
        else
        {
            ++argc;
            tmp = strchr(tmp, ' ');
        }
    }

    if (!argc)
    {
        pr_warn("no args found\n");
        return 0;
    }

    char **tmp_array = kzalloc(sizeof(char *) * (argc + 4), GFP_KERNEL);
    uint32_t index = 0;
    tmp = str;
    for (;;)
    {
        if (*tmp == '\0')
        {
            break;
        }

        if (*tmp == ' ')
        {
            tmp = skip_spaces(tmp);
        }
        else
        {
            // ++argc;
            tmp_array[index] = tmp;
            ++index;
            tmp = strchr(tmp, ' ');
            *tmp++ = '\0';
        }
    }

    *size = argc;
    *out = tmp_array;

    return 0;
}

void remove_string_line_break(char *str)
{
    char *tmp = str;
    for (;;)
    {
        uint32_t found_line_break = 0;
        char *p = strchr(tmp, '\n');
        if (p)
        {
            *p = ' ';
            tmp = p + 1;
            found_line_break = 1;
        }

        p = strchr(tmp, '\r');
        if (p)
        {
            *p = ' ';
            tmp = p + 1;
            found_line_break = 1;
        }

        if (!found_line_break)
        {
            break;
        }
    }
}
