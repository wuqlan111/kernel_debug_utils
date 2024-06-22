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

#include "debug_log.h"

#define IRQDESC_DEBUG_ROOT_DIR "irqdesc"
#define INVALID_IRQ_NUMBER (-1)

static int32_t export_irq = INVALID_IRQ_NUMBER;
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
    int32_t len = sprintf(tmp_str, "%d\n", get_export_irq());
    pr_debug("exported irq [%d]\n", get_export_irq());

    return simple_read_from_buffer(buf, count, ppos,
                                   tmp_str, len);
}

static ssize_t export_irqdesc_write(struct file *fp, const char __user *buf,
                                    size_t count, loff_t *ppos)
{
    char irq_str[64] = {0};
    int32_t tmp_irq = 0, ret = 0;
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

    long res = 0;
    ret = kstrtol(irq_str, 10, &res);
    tmp_irq = res;
    if (ret || tmp_irq < 0)
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

end:
    set_export_irq(tmp_irq);

    return len;
}

static const struct file_operations export_irqdesc_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = export_irqdesc_read,
    .write = export_irqdesc_write,
    .llseek = default_llseek,
};

static char *get_irq_trigger_type_str(uint32_t type)
{
    switch (type)
    {
        TYPE_CASE(IRQF_TRIGGER_NONE)
        TYPE_CASE(IRQF_TRIGGER_RISING)
        TYPE_CASE(IRQF_TRIGGER_FALLING)
        TYPE_CASE(IRQF_TRIGGER_HIGH)
        TYPE_CASE(IRQF_TRIGGER_LOW)
    }

    return "invalid irq trigger type";
}

static const bit_mask_descr_t irqdata_states[] = {
    BIT_MASK_DESCR(IRQ_TYPE_EDGE_RISING),
    BIT_MASK_DESCR(IRQ_TYPE_EDGE_FALLING),
    BIT_MASK_DESCR(IRQ_TYPE_LEVEL_HIGH),
    BIT_MASK_DESCR(IRQ_TYPE_LEVEL_LOW),
    BIT_MASK_DESCR(IRQD_LEVEL),

    BIT_MASK_DESCR(IRQD_ACTIVATED),
    BIT_MASK_DESCR(IRQD_IRQ_STARTED),
    BIT_MASK_DESCR(IRQD_IRQ_DISABLED),
    BIT_MASK_DESCR(IRQD_IRQ_MASKED),
    BIT_MASK_DESCR(IRQD_IRQ_INPROGRESS),

    BIT_MASK_DESCR(IRQD_PER_CPU),
    BIT_MASK_DESCR(IRQD_NO_BALANCING),

    BIT_MASK_DESCR(IRQD_SINGLE_TARGET),
    BIT_MASK_DESCR(IRQD_MOVE_PCNTXT),
    BIT_MASK_DESCR(IRQD_AFFINITY_SET),
    BIT_MASK_DESCR(IRQD_SETAFFINITY_PENDING),
    BIT_MASK_DESCR(IRQD_AFFINITY_MANAGED),
    BIT_MASK_DESCR(IRQD_MANAGED_SHUTDOWN),
    BIT_MASK_DESCR(IRQD_CAN_RESERVE),
    BIT_MASK_DESCR(IRQD_MSI_NOMASK_QUIRK),

    BIT_MASK_DESCR(IRQD_FORWARDED_TO_VCPU),

    BIT_MASK_DESCR(IRQD_WAKEUP_STATE),
    BIT_MASK_DESCR(IRQD_WAKEUP_ARMED),
};

static const bit_mask_descr_t irqchip_flags[] = {
    BIT_MASK_DESCR(IRQCHIP_SET_TYPE_MASKED),
    BIT_MASK_DESCR(IRQCHIP_EOI_IF_HANDLED),
    BIT_MASK_DESCR(IRQCHIP_MASK_ON_SUSPEND),
    BIT_MASK_DESCR(IRQCHIP_ONOFFLINE_ENABLED),
    BIT_MASK_DESCR(IRQCHIP_SKIP_SET_WAKE),
    BIT_MASK_DESCR(IRQCHIP_ONESHOT_SAFE),
    BIT_MASK_DESCR(IRQCHIP_EOI_THREADED),
    BIT_MASK_DESCR(IRQCHIP_SUPPORTS_LEVEL_MSI),
};

static ssize_t irqdesc_info_read(struct file *fp, char __user *buf,
                                 size_t count, loff_t *ppos)
{
    char tmp_str[1024] = {0};
    struct irq_desc *desc = irq_to_desc(get_export_irq());
    if (!desc)
    {
        return -EINVAL;
    }

#define CPU_MASK_VAR(x) ((x) ? (x)->bits[0] : (0ul))

    int32_t len = sprintf(tmp_str, "irq: %d\n", get_export_irq());
    len += sprintf(tmp_str + len, "hw_irq: %lu\n", desc->irq_data.hwirq);
    len += sprintf(tmp_str + len, "parent_irq: %d\n", desc->parent_irq);
    len += sprintf(tmp_str + len, "irq_name: %s\n", STRING_OR_NULL(desc->name));
    len += sprintf(tmp_str + len, "irq_chip: %s\n", STRING_OR_NULL(desc->irq_data.chip->name));
    len += sprintf(tmp_str + len, "irq_domain: %s\n", STRING_OR_NULL(desc->irq_data.domain->name));
    len += sprintf(tmp_str + len, "irq_trigger_type: %s\n",
                   get_irq_trigger_type_str(irqd_get_trigger_type(&desc->irq_data)));
    len += sprintf(tmp_str + len, "status_use_accessors: %#x\n",
                   desc->status_use_accessors);
    len += sprintf(tmp_str + len, "depth: %#x\n", desc->depth);
    len += sprintf(tmp_str + len, "percpu_enabled: %#lx\n", CPU_MASK_VAR(desc->percpu_enabled));
    len += sprintf(tmp_str + len, "percpu_affinity: %#lx\n", CPU_MASK_VAR(desc->percpu_affinity));

#ifdef CONFIG_SMP
    len += sprintf(tmp_str + len, "affinity_hint: %#lx\n", CPU_MASK_VAR(desc->affinity_hint));
#ifdef CONFIG_GENERIC_PENDING_IRQ
    len += sprintf(tmp_str + len, "pending_mask: %#lx\n", CPU_MASK_VAR(desc->pending_mask));
#endif
#endif

#ifdef CONFIG_NUMA
    len += sprintf(tmp_str + len, "irq_common_data.node: %d\n", desc->irq_common_data.node);
#endif
    len += sprintf(tmp_str + len, "irq_common_data.state_use_accessors: %#x\n",
                   desc->irq_common_data.state_use_accessors);
    len += sprintf(tmp_str + len, "irq_common_data.affinity: %#lx\n",
                   CPU_MASK_VAR(desc->irq_common_data.affinity));
#ifdef CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK
    len += sprintf(tmp_str + len, "irq_common_data.effective_affinity: %#lx\n",
                   CPU_MASK_VAR(desc->irq_common_data.effective_affinity));
#endif
#ifdef CONFIG_GENERIC_IRQ_IPI
    len += sprintf(tmp_str + len, "irq_common_data.ipi_offset: %u\n", desc->irq_common_data.ipi_offset);
#endif

    return simple_read_from_buffer(buf, count, ppos,
                                   tmp_str, len);
}

static const struct file_operations irqdesc_info_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = irqdesc_info_read,
    .llseek = default_llseek,
};

static ssize_t affinity_hint_write(struct file *fp, const char __user *buf,
                                   size_t count, loff_t *ppos)
{
    char irq_str[64] = {0};
    int32_t ret = 0;
    int32_t len = simple_write_to_buffer(irq_str, sizeof(irq_str), ppos, buf, count);
    cpumask_var_t m = {0};

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

    unsigned long res = 0;
    ret = kstrtol(irq_str, 16, &res);
    if (ret)
    {
        len = -EPERM;
        pr_err("user cpu mask [%s] invalid\n", irq_str);
        goto end;
    }

    if (!zalloc_cpumask_var(&m, GFP_KERNEL))
    {
        len = -ENOMEM;
        goto end;
    }

    for (uint32_t i = 0; i < 32; ++i)
    {
        if (res & BIT(i))
        {
            cpumask_set_cpu(i, m);
        }
    }

    ret = irq_set_affinity_hint(get_export_irq(), m);
    if (ret)
    {
        len = ret;
    }

end:
    return len;
}

static const struct file_operations affinity_hint_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .write = affinity_hint_write,
    .llseek = default_llseek,
};

static debugfs_file_init_t irqdesc_debugsf_files[] = {
    INIT_DEBUGFS_FILE_CREATE(export_irqdesc, NULL, 0666),
    INIT_DEBUGFS_FILE_CREATE(irqdesc_info, NULL, 0444),
    INIT_DEBUGFS_FILE_CREATE(affinity_hint, NULL, 0222),
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
