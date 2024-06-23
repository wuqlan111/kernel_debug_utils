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
#include <linux/interrupt.h>
#include <linux/string.h>

#include "debug_log.h"

#define IRQDOMAIN_DEBUG_ROOT_DIR "irqdomain"
#define DEFAULT_IRQ_DOMAIN_CONFIG "default_irqdomain"
#define IRQ_DOMAIN_LIST_CONFIG "irqdomain_list"

static struct list_head *global_irqdomain_list = NULL;
static struct irq_domain **default_irq_domain = NULL;
static char cur_irqdomain_name[128] = {0};

static inline void set_export_irqdomains_list(void *irqdomains)
{
    global_irqdomain_list = irqdomains;
}

static inline struct list_head *get_export_irqdomains_list(void)
{
    return global_irqdomain_list;
}

static inline void set_export_default_irq_domain(void *irqdomain)
{
    default_irq_domain = irqdomain;
}

static inline struct irq_domain **get_export_default_irq_domain(void)
{
    return default_irq_domain;
}

static ssize_t export_irqdomain_config_read(struct file *fp, char __user *buf,
                                            size_t count, loff_t *ppos)
{
    char tmp_str[128] = {0};
    int32_t len = sprintf(tmp_str, IRQ_DOMAIN_LIST_CONFIG ": 0x%p\n",
                          get_export_irqdomains_list());
    len += sprintf(tmp_str + len, DEFAULT_IRQ_DOMAIN_CONFIG ": 0x%p\n",
                   get_export_default_irq_domain());
    return simple_read_from_buffer(buf, count, ppos,
                                   tmp_str, len);
}

static ssize_t export_irqdomain_config_write(struct file *fp, const char __user *buf,
                                             size_t count, loff_t *ppos)
{
    char irq_str[128] = {0};
    int32_t ret = 0;
    int32_t len = simple_write_to_buffer(irq_str, sizeof(irq_str), ppos, buf, count);
    void *tmp_lists = NULL;

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
        p = skip_spaces(p + 1);
    }
    else
    {
        p = irq_str;
    }

    long res = 0;
    ret = kstrtoul(p, 16, &res);
    tmp_lists = UINT_TO_POINTER(res);
    if (ret)
    {
        len = -EPERM;
        tmp_lists = NULL;
        pr_err("user config val [%s] invalid\n", p);
        goto end;
    }

    if (!strcmp(irq_str, IRQ_DOMAIN_LIST_CONFIG))
    {
        set_export_irqdomains_list(tmp_lists);
    }
    else if (!strcmp(irq_str, DEFAULT_IRQ_DOMAIN_CONFIG))
    {
        set_export_default_irq_domain(tmp_lists);
    }
    else
    {
        pr_err("set option [%s] invalid!\n", irq_str);
        len = -EINVAL;
    }

end:
    return len;
}

static const struct file_operations export_irqdomain_config_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = export_irqdomain_config_read,
    .write = export_irqdomain_config_write,
    .llseek = default_llseek,
};

static struct irq_domain *find_irq_domain_by_name(const char *name)
{
    int32_t found = 0;
    struct irq_domain *ret = NULL;
    const struct list_head *irqdomains = get_export_irqdomains_list();
    if (!name || !irqdomains)
    {
        return NULL;
    }

    list_for_each_entry(ret, irqdomains, link)
    {
        if (!strcmp(ret->name, name))
        {
            found = 1;
            break;
        }
    }

    ret = found ? ret : NULL;
    return ret;
}

static ssize_t export_irqdomain_read(struct file *fp, char __user *buf,
                                     size_t count, loff_t *ppos)
{
    return simple_read_from_buffer(buf, count, ppos,
                                   cur_irqdomain_name, strlen(cur_irqdomain_name));
}

static ssize_t export_irqdomain_write(struct file *fp, const char __user *buf,
                                      size_t count, loff_t *ppos)
{
    int32_t len = simple_write_to_buffer(cur_irqdomain_name, sizeof(cur_irqdomain_name),
                                         ppos, buf, count);

    char *p = strchr(cur_irqdomain_name, '\r');
    if (p)
    {
        *p = '\0';
    }
    p = strchr(cur_irqdomain_name, '\n');
    if (p)
    {
        *p = '\0';
    }

    if (!find_irq_domain_by_name(cur_irqdomain_name))
    {
        pr_err("irq domain [%s] not exists!\n", cur_irqdomain_name);
        memset(cur_irqdomain_name, 0, sizeof(cur_irqdomain_name));
        len = -EINVAL;
    }

    return len;
}

static const struct file_operations export_irqdomain_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = export_irqdomain_read,
    .write = export_irqdomain_write,
    .llseek = default_llseek,
};

static char *irq_domain_bus_token_str(uint32_t token)
{
    switch (token)
    {
        TYPE_CASE(DOMAIN_BUS_ANY)
        TYPE_CASE(DOMAIN_BUS_WIRED)
        TYPE_CASE(DOMAIN_BUS_PCI_MSI)
        TYPE_CASE(DOMAIN_BUS_PLATFORM_MSI)
        TYPE_CASE(DOMAIN_BUS_NEXUS)
        TYPE_CASE(DOMAIN_BUS_IPI)
        TYPE_CASE(DOMAIN_BUS_FSL_MC_MSI)
    }

    return "invalid bus token";
}

static ssize_t irqdomain_info_read(struct file *fp, char __user *buf,
                                   size_t count, loff_t *ppos)
{
    char tmp_buf[512] = {0};
    int32_t len = 0;
    struct irq_domain *domain = find_irq_domain_by_name(cur_irqdomain_name);
    if (!domain)
    {
        return -EINVAL;
    }

    len = sprintf(tmp_buf, "name: %s\n", domain->name);
    len += sprintf(tmp_buf + len, "flags: %#x\n", domain->flags);
    len += sprintf(tmp_buf + len, "map_count: %u\n", domain->mapcount);
    len += sprintf(tmp_buf + len, "bus_token: %s\n",
                   irq_domain_bus_token_str(domain->bus_token));
#ifdef CONFIG_IRQ_DOMAIN_HIERARCHY
    if (domain->parent)
    {
        len += sprintf(tmp_buf + len, "parent: %s\n",
                       STRING_OR_NULL(domain->parent->name));
    }
#endif

    len += sprintf(tmp_buf + len, "hwirq_max: %lu\n", domain->hwirq_max);
    len += sprintf(tmp_buf + len, "revmap_direct_max_irq: %u\n",
                   domain->revmap_direct_max_irq);
    len += sprintf(tmp_buf + len, "revmap_size: %u\n", domain->revmap_size);

    return simple_read_from_buffer(buf, count, ppos,
                                   tmp_buf, len);
}

static const struct file_operations irqdomain_info_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = irqdomain_info_read,
    .llseek = default_llseek,
};

static ssize_t default_irqdomain_read(struct file *fp, char __user *buf,
                                      size_t count, loff_t *ppos)
{
    struct irq_domain *domain = *get_export_default_irq_domain();
    if (!domain)
    {
        return -EINVAL;
    }

    return simple_read_from_buffer(buf, count, ppos, STRING_OR_NULL(domain->name),
                                   strlen(STRING_OR_NULL(domain->name)));
}

static const struct file_operations default_irqdomain_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = default_irqdomain_read,
    .llseek = default_llseek,
};

static ssize_t existed_irqdomain_read(struct file *fp, char __user *buf,
                                      size_t count, loff_t *ppos)
{
    char tmp_str[512] = {0};
    int32_t len = 0;
    struct irq_domain *domain = NULL;
    const struct list_head *irqdomains = get_export_irqdomains_list();
    if (!irqdomains)
    {
        return -EINVAL;
    }

    list_for_each_entry(domain, irqdomains, link)
    {
        len += snprintf(tmp_str + len, sizeof(tmp_str) - len, "%s\n", domain->name);
    }

    return simple_read_from_buffer(buf, count, ppos, tmp_str,
                                   len);
}

static const struct file_operations existed_irqdomain_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = existed_irqdomain_read,
    .llseek = default_llseek,
};

static debugfs_file_init_t irqdomain_debugsf_files[] = {
    INIT_DEBUGFS_FILE_CREATE(export_irqdomain_config, NULL, 0666),
    INIT_DEBUGFS_FILE_CREATE(export_irqdomain, NULL, 0666),
    INIT_DEBUGFS_FILE_CREATE(irqdomain_info, NULL, 0444),
    INIT_DEBUGFS_FILE_CREATE(default_irqdomain, NULL, 0444),
    INIT_DEBUGFS_FILE_CREATE(existed_irqdomain, NULL, 0444),
};

int32_t debug_irqdomain_init(struct dentry *irq_root_dir)
{
    int32_t ret = 0;
    if (!irq_root_dir)
    {
        return -EPERM;
    }

    struct dentry *dir = debugfs_create_dir(IRQDOMAIN_DEBUG_ROOT_DIR, irq_root_dir);
    if (!dir)
    {
        pr_err("init irqdomain debug failed!\n");
        return -EINVAL;
    }

    for (int32_t i = 0; i < ARRAY_SIZE(irqdomain_debugsf_files); ++i)
    {
        if (!debugfs_create_file(irqdomain_debugsf_files[i].name, irqdomain_debugsf_files[i].mode,
                                 dir, irqdomain_debugsf_files[i].data, irqdomain_debugsf_files[i].fops))
        {
            ret = -EINVAL;
            pr_err("create " IRQDOMAIN_DEBUG_ROOT_DIR "/%s failed",
                   irqdomain_debugsf_files[i].name);
            break;
        }
    }

    return ret;
}
