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
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>

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

    len = sprintf(tmp_buf, "\n\n**slef**: 0x%p\n", node);
    len += sprintf(tmp_buf + len, "imode: %#x\n", node->i_mode);
    len += sprintf(tmp_buf + len, "i_opflags: %#x\n", node->i_opflags);
    len += sprintf(tmp_buf + len, "uid: %u\n", node->i_uid.val);
    len += sprintf(tmp_buf + len, "gid: %u\n", node->i_gid.val);
    len += sprintf(tmp_buf + len, "flags: %#x\n", node->i_flags);
    len += sprintf(tmp_buf + len, "inode_ops: 0x%p\n", node->i_op);
    len += sprintf(tmp_buf + len, "super_block: 0x%p\n", node->i_sb);
    len += sprintf(tmp_buf + len, "super_block_name: %s\n",
                   STRING_OR_NULL(node->i_sb->s_type->name));
    len += sprintf(tmp_buf + len, "i_mapping: 0x%p\n", node->i_mapping);
    len += sprintf(tmp_buf + len, "i_data: 0x%p\n", &node->i_data);
    len += sprintf(tmp_buf + len, "ino: %#lx\n", node->i_ino);
    len += sprintf(tmp_buf + len, "i_nlink: %#x\n", node->i_nlink);
    len += sprintf(tmp_buf + len, "i_rdev: %#x\n", node->i_rdev);
    len += sprintf(tmp_buf + len, "i_size: %#llx\n", node->i_size);
    len += sprintf(tmp_buf + len, "i_bytes: %#x\n", node->i_bytes);
    len += sprintf(tmp_buf + len, "i_blkbits: %#x\n", node->i_blkbits);
    len += sprintf(tmp_buf + len, "i_write_hint: %#x\n", node->i_write_hint);
    len += sprintf(tmp_buf + len, "i_blocks: %#llx\n", node->i_blocks);
    len += sprintf(tmp_buf + len, "i_state: %#lx\n", node->i_state);

    len += sprintf(tmp_buf + len, "\n");
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

    len = sprintf(tmp_buf, "\n\n**slef**: 0x%p\n", entry);
    len += sprintf(tmp_buf + len, "d_flags: %#x\n", entry->d_flags);
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

    len += sprintf(tmp_buf + len, "\n");
    return simple_read_from_buffer(buf, count, ppos, tmp_buf,
                                   strlen(tmp_buf));
}

static const struct file_operations file_dentry_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = file_dentry_read,
    .llseek = default_llseek,
};

static ssize_t file_sb_read(struct file *fp, char __user *buf,
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

    struct super_block *sb = file_path.dentry->d_sb;
    if (!sb)
    {
        pr_err("no fs super block found!\n");
        return -EINVAL;
    }

    len = sprintf(tmp_buf, "\n\n**slef**: 0x%p\n", sb);
    len += sprintf(tmp_buf + len, "s_dev: %#x\n", sb->s_dev);
    len += sprintf(tmp_buf + len, "s_blocksize: %lu\n", sb->s_blocksize);
    len += sprintf(tmp_buf + len, "s_blocksize_bits: %u\n", sb->s_blocksize_bits);
    len += sprintf(tmp_buf + len, "s_maxbytes: %llu\n", sb->s_maxbytes);
    len += sprintf(tmp_buf + len, "s_type: %s\n", STRING_OR_NULL(sb->s_type->name));
    len += sprintf(tmp_buf + len, "s_flags: %#lx\n", sb->s_flags);
    len += sprintf(tmp_buf + len, "s_iflags: %#lx\n", sb->s_iflags);
    len += sprintf(tmp_buf + len, "s_magic: %#lx\n", sb->s_magic);
    len += sprintf(tmp_buf + len, "s_root: 0x%p\n", sb->s_root);
    len += sprintf(tmp_buf + len, "s_root_dname: %s\n", STRING_OR_NULL(sb->s_root->d_iname));
    len += sprintf(tmp_buf + len, "s_root_iname: %s\n", STRING_OR_NULL(sb->s_root->d_name.name));
    len += sprintf(tmp_buf + len, "s_count: %d\n", sb->s_count);
    len += sprintf(tmp_buf + len, "s_active: %d\n", sb->s_active.counter);
    len += sprintf(tmp_buf + len, "s_bdev: 0x%p\n", sb->s_bdev);
    len += sprintf(tmp_buf + len, "s_bdi: 0x%p\n", sb->s_bdi);
    len += sprintf(tmp_buf + len, "s_mtd: 0x%p\n", sb->s_mtd);
    len += sprintf(tmp_buf + len, "s_mode: %#x\n", sb->s_mode);

    len += sprintf(tmp_buf + len, "\n");
    return simple_read_from_buffer(buf, count, ppos, tmp_buf,
                                   strlen(tmp_buf));
}

static const struct file_operations file_sb_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = file_sb_read,
    .llseek = default_llseek,
};

static ssize_t file_block_dev_read(struct file *fp, char __user *buf,
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

    struct super_block *sb = file_path.dentry->d_sb;
    if (!sb || !sb->s_bdev)
    {
        pr_err("no file block dev found!\n");
        return -EINVAL;
    }

    struct block_device *bdev = sb->s_bdev;

    len = sprintf(tmp_buf, "\n\n**slef**: 0x%p\n", bdev);
    len += sprintf(tmp_buf + len, "bd_dev: %#x\n", bdev->bd_dev);
    len += sprintf(tmp_buf + len, "bd_dev: %#x\n", bdev->bd_openers);
    len += sprintf(tmp_buf + len, "bd_inode: 0x%p\n", bdev->bd_inode);
    if (bdev->bd_inode)
    {
        len += sprintf(tmp_buf + len, "bd_inode_sb: 0x%p\n", bdev->bd_inode->i_sb);
    }
    len += sprintf(tmp_buf + len, "bd_super: 0x%p\n", bdev->bd_super);
    len += sprintf(tmp_buf + len, "bd_holder: 0x%p\n", bdev->bd_holder);
    len += sprintf(tmp_buf + len, "bd_holders: %d\n", bdev->bd_holders);
    len += sprintf(tmp_buf + len, "bd_write_holder: %s\n", BOOL_TO_STR(bdev->bd_write_holder));
    len += sprintf(tmp_buf + len, "bd_contains: 0x%p\n", bdev->bd_contains);
    // len += sprintf(tmp_buf + len, "bd_block_size: %u\n", bdev->bd_block_size);
    len += sprintf(tmp_buf + len, "bd_partno: %u\n", bdev->bd_partno);
    len += sprintf(tmp_buf + len, "bd_part_count: %u\n", bdev->bd_part_count);
    // len += sprintf(tmp_buf + len, "bd_invalidated: %d\n", bdev->bd_invalidated);
    len += sprintf(tmp_buf + len, "bd_disk: 0x%p\n", bdev->bd_disk);
    if (bdev->bd_disk)
    {
        len += sprintf(tmp_buf + len, "bd_disk.name: %s\n", bdev->bd_disk->disk_name);
    }

#if 0
    len += sprintf(tmp_buf + len, "bd_queue: 0x%p\n", bdev->bd_queue);
    if (bdev->bd_queue)
    {
        len += sprintf(tmp_buf + len, "bd_queue.bdi: 0x%p\n", bdev->bd_queue->backing_dev_info);
        len += sprintf(tmp_buf + len, "bd_queue.bdi.name: 0x%p\n",
                       STRING_OR_NULL(bdev->bd_queue->backing_dev_info->name));
        len += sprintf(tmp_buf + len, "bd_queue.bdi.dev_name: 0x%p\n",
                       STRING_OR_NULL(bdev->bd_queue->backing_dev_info->dev_name));
    }
#endif

    len += sprintf(tmp_buf + len, "bd_bdi: %p\n", bdev->bd_bdi);
    if (bdev->bd_bdi)
    {
        // len += sprintf(tmp_buf + len, "bd_bdi.name: %s\n",
        //                STRING_OR_NULL(bdev->bd_bdi->name));
        len += sprintf(tmp_buf + len, "bd_bdi.dev_name: %s\n",
                       STRING_OR_NULL(bdev->bd_bdi->dev_name));
    }

    len += sprintf(tmp_buf + len, "\n");
    return simple_read_from_buffer(buf, count, ppos, tmp_buf,
                                   strlen(tmp_buf));
}

static const struct file_operations file_block_dev_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = file_block_dev_read,
    .llseek = default_llseek,
};

#define FILE_ADDRESS_SPACE_DUMP_MAX (128u)
static struct
{
    uint8_t is_dump;
    uint8_t is_mapping;
    uint32_t page_idx;
    uint32_t page_offset;
    uint32_t len;
} file_address_space_cmd_args = {0};
static ssize_t file_address_space_write(struct file *fp, const char __user *buf,
                                        size_t count, loff_t *ppos)
{
    int32_t ret = 0;
    char tmp_str[256] = {0};
    int32_t len = simple_write_to_buffer(tmp_str, sizeof(tmp_str),
                                         ppos, buf, count);

    if (len < count)
    {
        return -EPERM;
    }

    remove_string_line_break(tmp_str);

    char **argv = NULL;
    uint32_t argc = 0;
    ret = get_cmd_args_from_string(tmp_str, &argv, &argc);
    if (ret || !argv || !argc)
    {
        len = -EPERM;
        pr_err("input cmd args invalid\n");
        goto end;
    }

    uint32_t is_dump = 0;
    if (!strcmp(argv[0], "dump"))
    {
        is_dump = 1;
    }
    else if (!strcmp(argv[0], "show"))
    {
        is_dump = 0;
    }
    else
    {
        len = -EPERM;
        pr_err("ops [ %s ] invalid\n", argv[0]);
        goto end;
    }

    if ((is_dump && (argc != 5)) || (!is_dump && (argc != 2)))
    {
        len = -EPERM;
        pr_err("cmd args count [%u] invalid!\n", argc);
        goto end;
    }

    uint32_t is_mapping = 0;
    if (!strcmp(argv[1], "i_mapping"))
    {
        is_mapping = 1;
    }
    else if (!strcmp(argv[1], "i_data"))
    {
        is_mapping = 0;
    }
    else
    {
        pr_err("address space [%s] invalid!\n", argv[1]);
        len = -EPERM;
        goto end;
    }

    ret = 0;
    unsigned long page_idx = 0, page_offset = 0, dump_len = 0;
    if (is_dump)
    {
        ret = kstrtoul(argv[2], 16, &page_idx);
        ret |= kstrtoul(argv[3], 16, &page_offset);
        ret |= kstrtoul(argv[4], 10, &dump_len);
    }

    if (ret || ((dump_len + page_offset) > PHYSICAL_PAGE_SIZE) ||
        (dump_len > FILE_ADDRESS_SPACE_DUMP_MAX))
    {
        len = -EPERM;
        goto end;
    }

    file_address_space_cmd_args.is_dump = is_dump;
    file_address_space_cmd_args.is_mapping = is_mapping;
    file_address_space_cmd_args.page_idx = page_idx;
    file_address_space_cmd_args.page_offset = page_offset;
    file_address_space_cmd_args.len = len;

end:
    if (argv)
    {
        kfree(argv);
    }
    if (len < 0)
    {
        pr_notice("usage: show|dump i_mapping|i_data [page_idx] [page_offset] [len]\n");
    }

    return len;
}

static int32_t show_file_address_space(const struct address_space *mapping, char *buf, uint32_t size)
{
    int32_t len = 0;
    if (!mapping || !buf || !size)
    {
        return -EPERM;
    }

    len = sprintf(buf, "\n\n**slef**: 0x%p\n", mapping);
    len += sprintf(buf + len, "host: 0x%p\n", mapping->host);
    len += sprintf(buf + len, "nrpages: %lu\n", mapping->nrpages);
    len += sprintf(buf + len, "nrexceptional: %lu\n", mapping->nrexceptional);
    len += sprintf(buf + len, "writeback_index: %lu\n", mapping->writeback_index);
    len += sprintf(buf + len, "a_ops: 0x%p\n", mapping->a_ops);
    len += sprintf(buf + len, "flags: %#lx\n", mapping->flags);
    len += sprintf(buf + len, "gfp_mask: %#x\n", mapping->gfp_mask);
    len += sprintf(buf + len, "wb_err: %#x\n", mapping->wb_err);
    len += sprintf(buf + len, "\n\n");

    return len;
}

typedef struct page *(*find_get_entry_func_t)(struct address_space *, pgoff_t);
static int32_t dump_file_address_space(struct address_space *mapping, char *buf, uint32_t size,
                                       pgoff_t page_idx, uint32_t page_offset, uint32_t len)
{
    int32_t outlen = 0;
    if (!mapping || !buf || !size)
    {
        return -EPERM;
    }

    find_get_entry_func_t find_get_entry_func = NULL;
    find_get_entry_func = debug_utils_get_kernel_symbol("find_get_entry");
    if (!find_get_entry_func)
    {
        pr_err("get find_get_entry kallsym failed!\n");
        return -EINVAL;
    }

    struct page *pg = find_get_entry_func(mapping, page_idx);
    if (!pg)
    {
        pr_warn("address_space [ 0x%p ] don't find page [ %lu ]\n", mapping, page_idx);
        return -EPERM;
    }

    outlen = sprintf(buf, "\n\n**slef**: 0x%p\n", pg);
    outlen += sprintf(buf + outlen, "flags: %#lx\n", pg->flags);
    outlen += sprintf(buf + outlen, "mapping: 0x%p\n", pg->mapping);
    outlen += sprintf(buf + outlen, "index: %lu\n", pg->index);
    outlen += sprintf(buf + outlen, "private: %#lx\n", pg->private);
    outlen += sprintf(buf + outlen, "_mapcount: %d\n", pg->_mapcount.counter);
    outlen += sprintf(buf + outlen, "page_type: %#x\n", pg->page_type);
    outlen += sprintf(buf + outlen, "_refcount: %d\n", pg->_refcount.counter);

#if defined(WANT_PAGE_VIRTUAL)
    outlen += sprintf(buf + outlen, "flags: %#x\n", pg->virtual);
#endif
    outlen += sprintf(buf + outlen, "\n\n");

    if (((page_offset + len) > PHYSICAL_PAGE_SIZE) || (len > FILE_ADDRESS_SPACE_DUMP_MAX))
    {
        pr_warn("page_offset [%u] and len [%u] invalid\n", page_offset, len);
        goto end;
    }

    void *map_addr = kmap(pg);
    pr_info("map page [ 0x%p ] to addr [ 0x%p ]\n", pg, map_addr);
    if (!map_addr)
    {
        pr_warn("map page to kernel failed!\n");
        goto end;
    }

    outlen += sprintf(buf + outlen, "=====dump page data=====\n");
    const uint8_t *page_data = (uint8_t *)map_addr + page_offset;
    outlen += debug_utils_dump_data(page_data, len, buf + outlen);
    outlen += sprintf(buf + outlen, "\n\n");
    kunmap(pg);

end:
    return outlen;
}

static ssize_t file_address_space_read(struct file *fp, char __user *buf,
                                       size_t count, loff_t *ppos)
{
    int32_t ret = 0;
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

    uint32_t is_dump = file_address_space_cmd_args.is_dump;
    uint32_t is_mapping = file_address_space_cmd_args.is_mapping;
    uint32_t page_idx = file_address_space_cmd_args.page_idx;
    uint32_t page_offset = file_address_space_cmd_args.page_offset;
    uint32_t dump_len = file_address_space_cmd_args.len;

    struct address_space *address =
        is_mapping ? file_path.dentry->d_inode->i_mapping : &file_path.dentry->d_inode->i_data;
    if (!address)
    {
        pr_err("no inode address space found!\n");
        return -EINVAL;
    }

    char tmp_buf[1024] = {0};
    int32_t len = 0;
    if (is_dump)
    {
        len = dump_file_address_space(address, tmp_buf, sizeof(tmp_buf),
                                      page_idx, page_offset, dump_len);
    }
    else
    {
        len = show_file_address_space(address, tmp_buf, sizeof(tmp_buf));
    }

    len = simple_read_from_buffer(buf, count, ppos, tmp_buf,
                                  strlen(tmp_buf));

    return len;
}

static const struct file_operations file_address_space_fops = {
    .owner = THIS_MODULE,
    .open = simple_open,
    .read = file_address_space_read,
    .write = file_address_space_write,
    .llseek = default_llseek,
};

static debugfs_file_init_t file_info_files[] = {
    INIT_DEBUGFS_FILE_CREATE(export_filename, NULL, 0666),
    INIT_DEBUGFS_FILE_CREATE(file_inode, NULL, 0444),
    INIT_DEBUGFS_FILE_CREATE(file_dentry, NULL, 0444),
    INIT_DEBUGFS_FILE_CREATE(file_sb, NULL, 0444),
    INIT_DEBUGFS_FILE_CREATE(file_block_dev, NULL, 0444),
    INIT_DEBUGFS_FILE_CREATE(file_address_space, NULL, 0666),
    // INIT_DEBUGFS_FILE_CREATE(irqdomain_info, NULL, 0444),
    // INIT_DEBUGFS_FILE_CREATE(default_irqdomain, NULL, 0444),
    // INIT_DEBUGFS_FILE_CREATE(existed_irqdomain, NULL, 0444),
};

int32_t debug_file_info_init(struct dentry *irq_root_dir)
{
    return debug_utils_common_init(irq_root_dir, FILE_INFO_ROOT_DIR,
                                   file_info_files, ARRAY_SIZE(file_info_files));
}
