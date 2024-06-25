#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/fs.h>

#include "debug_log.h"
#include "debug_utils.h"

#define FILE_INFO_ROOT_DIR "file_info"

static struct filename *export_file_name = NULL;

static inline void set_export_file_name(void *filename)
{
    export_file_name = filename;
}

static inline struct filename *get_export_file_name(void)
{
    return export_file_name;
}

static ssize_t export_filename_read(struct file *fp, char __user *buf,
                                    size_t count, loff_t *ppos)
{
    int32_t len = 0, tmp_len = 0;
    char *tmp_buf = kmalloc(PATH_MAX + 512, GFP_KERNEL);
    if (!tmp_buf)
    {
        return -ENOMEM;
    }

    struct filename *filename = get_export_file_name();
    if (!filename)
    {
        return -EINVAL;
    }

    tmp_len = sprintf(tmp_buf, "name: %s\n", STRING_OR_NULL(filename->name));
    tmp_len += sprintf(tmp_buf + tmp_len, "refcnt: %u\n", filename->refcnt);
    tmp_len += sprintf(tmp_buf + tmp_len, "extern_space: %s\n",
                       filename->name == filename->iname ? "false" : "true");

    len = simple_read_from_buffer(buf, count, ppos, tmp_buf,
                                  strlen(tmp_buf));

    kfree(tmp_buf);
    return len;
}

typedef struct filename *(*getname_func_t)(const char __user *);
typedef void (*putname_func_t)(struct filename *name);

static ssize_t export_filename_write(struct file *fp, const char __user *buf,
                                     size_t count, loff_t *ppos)
{
    char irq_str[1024] = {0};
    int32_t len = simple_write_to_buffer(irq_str, sizeof(irq_str), ppos, buf, count);

    if (irq_str[0] != '/')
    {
        pr_err("only full filename\n");
        return -EINVAL;
    }

    getname_func_t getname_func = NULL;
    putname_func_t putname_func = NULL;
    getname_func = debug_utils_get_kernel_symbol("getname");
    putname_func = debug_utils_get_kernel_symbol("putname");
    if (!getname_func || !putname_func)
    {
        pr_err("get filename func symbol failed!\n");
        return -EINVAL;
    }

    struct filename *ori = NULL;
    struct filename *file = getname_func(buf);
    if (!file)
    {
        len = -EPERM;
        goto end;
    }
    else
    {
        ori = get_export_file_name();
        set_export_file_name(file);
    }

    char *p = strchr(file->name, '\r');
    if (p)
    {
        *p = '\0';
    }
    p = strchr(file->name, '\n');
    if (p)
    {
        *p = '\0';
    }

    if (ori)
    {
        putname_func(ori);
    }

end:
    return len;
}

static const struct file_operations export_filename_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = export_filename_read,
    .write = export_filename_write,
    .llseek = default_llseek,
};

static ssize_t file_inode_read(struct file *fp, char __user *buf,
                               size_t count, loff_t *ppos)
{
    int32_t len = 0, ret = 0;
    char tmp_buf[1024] = {0};
    struct path file_path;
    uint32_t flags = 0;

    ret = kern_path(get_export_file_name()->name, flags, &file_path);
    if (ret)
    {
        flags |= LOOKUP_DIRECTORY;
        ret = kern_path(get_export_file_name()->name, flags, &file_path);
    }

    if (ret)
    {
        return ret;
    }

    struct inode *node = file_path.dentry->d_inode;
    if (!node)
    {
        pr_err("no file inode found!\n");
        return -EINVAL;
    }

    len = sprintf(tmp_buf, "imode: %#x\n", node->i_mode);
    len += sprintf(tmp_buf + len, "i_opflags: %#x\n", node->i_opflags);
    len += sprintf(tmp_buf + len, "uid: %u\n", node->i_uid.val);
    len += sprintf(tmp_buf + len, "gid: %u\n", node->i_gid.val);
    len += sprintf(tmp_buf + len, "flags: %#x\n", node->i_flags);
    len += sprintf(tmp_buf + len, "inode_ops: 0x%p\n", node->i_op);
    len += sprintf(tmp_buf + len, "super_block: 0x%p\n", node->i_sb);
    len += sprintf(tmp_buf + len, "super_block_name: %s\n",
                   STRING_OR_NULL(node->i_sb->s_type->name));
    len += sprintf(tmp_buf + len, "address_space: 0x%p\n", node->i_mapping);
    len += sprintf(tmp_buf + len, "ino: %#lx\n", node->i_ino);
    len += sprintf(tmp_buf + len, "i_nlink: %#x\n", node->i_nlink);
    len += sprintf(tmp_buf + len, "i_rdev: %#x\n", node->i_rdev);
    len += sprintf(tmp_buf + len, "i_size: %#llx\n", node->i_size);
    len += sprintf(tmp_buf + len, "i_bytes: %#x\n", node->i_bytes);
    len += sprintf(tmp_buf + len, "i_blkbits: %#x\n", node->i_blkbits);
    len += sprintf(tmp_buf + len, "i_write_hint: %#x\n", node->i_write_hint);
    len += sprintf(tmp_buf + len, "i_blocks: %#llx\n", node->i_blocks);
    len += sprintf(tmp_buf + len, "i_state: %#lx\n", node->i_state);

    return simple_read_from_buffer(buf, count, ppos, tmp_buf,
                                   strlen(tmp_buf));
}

static const struct file_operations file_inode_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = file_inode_read,
    .llseek = default_llseek,
};

static ssize_t file_dentry_read(struct file *fp, char __user *buf,
                                size_t count, loff_t *ppos)
{
    int32_t len = 0, ret = 0;
    char tmp_buf[1024] = {0};
    struct path file_path;
    uint32_t flags = 0;

    ret = kern_path(get_export_file_name()->name, flags, &file_path);
    if (ret)
    {
        flags |= LOOKUP_DIRECTORY;
        ret = kern_path(get_export_file_name()->name, flags, &file_path);
    }

    if (ret)
    {
        return ret;
    }

    struct dentry *entry = file_path.dentry;
    if (!entry)
    {
        pr_err("no file dentry found!\n");
        return -EINVAL;
    }

    len = sprintf(tmp_buf, "imode: %#x\n", entry->d_flags);
    // len += sprintf(tmp_buf + len, "d_seq: %#x\n", entry->d_seq.sequence);
    len += sprintf(tmp_buf + len, "parent: 0x%p\n", entry->d_parent);
    len += sprintf(tmp_buf + len, "parent_name: %s\n", STRING_OR_NULL(entry->d_parent->d_name.name));
    len += sprintf(tmp_buf + len, "parent_iname: %s\n", entry->d_parent->d_iname);
    len += sprintf(tmp_buf + len, "d_name.name: %s\n", STRING_OR_NULL(entry->d_name.name));
    len += sprintf(tmp_buf + len, "d_name.len: %#x\n", entry->d_name.len);
    len += sprintf(tmp_buf + len, "d_name.hash: %#x\n", entry->d_name.hash);
    len += sprintf(tmp_buf + len, "d_inode: 0x%p\n", entry->d_inode);
    len += sprintf(tmp_buf + len, "d_iname: %s\n", entry->d_iname);
    len += sprintf(tmp_buf + len, "dentry_ops: 0x%p\n", entry->d_op);
    len += sprintf(tmp_buf + len, "d_sp: 0x%p\n", entry->d_sb);
    len += sprintf(tmp_buf + len, "sb_name: %s\n", STRING_OR_NULL(entry->d_sb->s_type->name));

    return simple_read_from_buffer(buf, count, ppos, tmp_buf,
                                   strlen(tmp_buf));
}

static const struct file_operations file_dentry_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = file_dentry_read,
    .llseek = default_llseek,
};

static debugfs_file_init_t file_info_files[] = {
    INIT_DEBUGFS_FILE_CREATE(export_filename, NULL, 0666),
    INIT_DEBUGFS_FILE_CREATE(file_inode, NULL, 0444),
    INIT_DEBUGFS_FILE_CREATE(file_dentry, NULL, 0444),
    // INIT_DEBUGFS_FILE_CREATE(export_irqdomain, NULL, 0666),
    // INIT_DEBUGFS_FILE_CREATE(irqdomain_info, NULL, 0444),
    // INIT_DEBUGFS_FILE_CREATE(default_irqdomain, NULL, 0444),
    // INIT_DEBUGFS_FILE_CREATE(existed_irqdomain, NULL, 0444),
};

int32_t debug_file_info_init(struct dentry *irq_root_dir)
{
    return debug_utils_common_init(irq_root_dir, FILE_INFO_ROOT_DIR,
                                   file_info_files, ARRAY_SIZE(file_info_files));
}
