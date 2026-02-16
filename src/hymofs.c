#include <linux/string.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fsnotify.h>
#include <linux/tty.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/dirent.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/sched/task.h>
#include <linux/xattr.h>
#include <linux/rcupdate.h>
#include <linux/utsname.h>
#include <linux/export.h>
#include <linux/miscdevice.h>
#include <linux/anon_inodes.h>
#include <linux/jhash.h>
#include <linux/version.h>
#include <linux/xarray.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0))
#include <linux/rbtree.h>
#endif
#include "mount.h"

#include <linux/hymofs.h>
#include <linux/hymo_magic.h>

#ifdef CONFIG_HYMOFS

/*
 * dir_context.actor return type: 5.10/5.15 use int (0=continue), 6.1+ use bool (true=continue).
 * Single source for all branches (5.10 / 5.15 / 6.1 / 6.6 / 6.12).
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0))
#define HYMO_FILLDIR_RET_TYPE int
#define HYMO_FILLDIR_CONTINUE 0
#define HYMO_FILLDIR_STOP 1
#else
#define HYMO_FILLDIR_RET_TYPE bool
#define HYMO_FILLDIR_CONTINUE true
#define HYMO_FILLDIR_STOP false
#endif

/* HymoFS - Advanced Path Manipulation and Hiding */
/* Increased hash bits to reduce collisions with large number of rules */
#define HYMO_HASH_BITS 12
#define HYMO_ALLOWLIST_UID_MAX 1024
#define HYMO_KSU_ALLOWLIST_PATH "/data/adb/ksu/.allowlist"
#define HYMO_KSU_ALLOWLIST_MAGIC 0x7f4b5355
#define HYMO_KSU_ALLOWLIST_VERSION 3
#define HYMO_KSU_MAX_PACKAGE_NAME 256
#define HYMO_KSU_MAX_GROUPS 32
#define HYMO_KSU_SELINUX_DOMAIN 64

struct hymo_linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[];
};

struct hymo_entry {
    char *src;
    char *target;
    unsigned char type;
    u32 src_hash; /* cached full_name_hash for hot path: compare before strcmp */
    struct hlist_node node;
    struct hlist_node target_node;
    struct rcu_head rcu;
};
struct hymo_hide_entry {
    char *path;
    u32 path_hash; /* cached full_name_hash for hot path */
    struct hlist_node node;
    struct rcu_head rcu;
};

/* Allowlist UIDs: stored in xarray by uid index; value is non-NULL marker */
#define HYMO_UID_ALLOW_MARKER ((void *)1)

struct hymo_root_profile {
    s32 uid;
    s32 gid;
    s32 groups_count;
    s32 groups[HYMO_KSU_MAX_GROUPS];
    struct {
        u64 effective;
        u64 permitted;
        u64 inheritable;
    } capabilities;
    char selinux_domain[HYMO_KSU_SELINUX_DOMAIN];
    s32 namespaces;
};

struct hymo_non_root_profile {
    bool umount_modules;
};

struct hymo_app_profile {
    u32 version;
    char key[HYMO_KSU_MAX_PACKAGE_NAME];
    s32 current_uid;
    bool allow_su;
    union {
        struct {
            bool use_default;
            char template_name[HYMO_KSU_MAX_PACKAGE_NAME];
            struct hymo_root_profile profile;
        } rp_config;
        struct {
            bool use_default;
            struct hymo_non_root_profile profile;
        } nrp_config;
    };
};

struct hymo_inject_entry {
    char *dir;
    struct hlist_node node;
    struct rcu_head rcu;
};

struct hymo_xattr_sb_entry {
    struct super_block *sb;
    struct hlist_node node;
    struct rcu_head rcu;
};

struct hymo_merge_entry {
    char *src;
    char *target;
    struct hlist_node node;
    struct rcu_head rcu;
};

/* Prefix trie for merge rules: longest-prefix match in one path walk */
struct hymo_merge_trie_node {
    char *comp;
    size_t comp_len;
    struct hymo_merge_trie_node *first_child;
    struct hymo_merge_trie_node *next_sibling;
    struct hymo_merge_entry *entry;
    struct rcu_head rcu; /* used only for root when freeing via call_rcu */
};

static struct hymo_merge_trie_node *hymo_merge_trie_root __rcu;
static DEFINE_SPINLOCK(hymo_merge_trie_lock);

static DEFINE_HASHTABLE(hymo_paths, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_targets, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_hide_paths, HYMO_HASH_BITS);
static DEFINE_XARRAY(hymo_allow_uids_xa);
static DEFINE_HASHTABLE(hymo_inject_dirs, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_xattr_sbs, HYMO_HASH_BITS);
static DEFINE_HASHTABLE(hymo_merge_dirs, HYMO_HASH_BITS);
/* Fine-grained locks to reduce contention (backported from hymofs_kpm) */
static DEFINE_SPINLOCK(hymo_cfg_lock);       /* enable/mirror path toggles */
static DEFINE_SPINLOCK(hymo_rules_lock);     /* hymo_paths + hymo_targets */
static DEFINE_SPINLOCK(hymo_hide_lock);      /* hymo_hide_paths */
static DEFINE_SPINLOCK(hymo_allow_uids_lock); /* hymo_allow_uids_xa */
static DEFINE_SPINLOCK(hymo_xattr_sbs_lock); /* hymo_xattr_sbs */
static DEFINE_SPINLOCK(hymo_merge_lock);      /* hymo_merge_dirs */
static DEFINE_SPINLOCK(hymo_inject_lock);    /* hymo_inject_dirs */
static bool hymo_allowlist_loaded = false;
static DEFINE_MUTEX(hymo_allowlist_lock);
bool hymofs_enabled = true;
EXPORT_SYMBOL(hymofs_enabled);

/* Use HYMO_BLOOM_BITS from hymofs.h to avoid redefinition */
static DECLARE_BITMAP(hymo_path_bloom, HYMO_BLOOM_SIZE);
static DECLARE_BITMAP(hymo_hide_bloom, HYMO_BLOOM_SIZE);
static atomic_t hymo_rule_count = ATOMIC_INIT(0);
static atomic_t hymo_hide_count = ATOMIC_INIT(0);

static bool hymo_debug_enabled = false;
module_param(hymo_debug_enabled, bool, 0644);
MODULE_PARM_DESC(hymo_debug_enabled, "Enable debug logging");
static bool hymo_stealth_enabled = true;

static char hymo_mirror_path_buf[PATH_MAX] = HYMO_DEFAULT_MIRROR_PATH;
static char hymo_mirror_name_buf[NAME_MAX] = HYMO_DEFAULT_MIRROR_NAME;
static char *hymo_current_mirror_path = hymo_mirror_path_buf;
static char *hymo_current_mirror_name = hymo_mirror_name_buf;

/* Daemon PID - automatically registered when GET_FD is called */
static pid_t hymo_daemon_pid = 0;
static DEFINE_SPINLOCK(hymo_daemon_lock);

#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
static bool hymo_reload_ksu_allowlist(void);
#endif

#define hymo_log(fmt, ...) do { \
    if (hymo_debug_enabled) \
        printk(KERN_INFO "hymofs: " fmt, ##__VA_ARGS__); \
} while(0)

/* Performance statistics */
struct hymofs_stats {
    atomic64_t total_checks;
    atomic64_t fast_path_skips;
    atomic64_t bloom_rejects;
    atomic64_t rule_hits;
};

static struct hymofs_stats hymo_stats = {
    .total_checks = ATOMIC64_INIT(0),
    .fast_path_skips = ATOMIC64_INIT(0),
    .bloom_rejects = ATOMIC64_INIT(0),
    .rule_hits = ATOMIC64_INIT(0),
};

static struct hymo_uname_info {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
} hymo_uname_info = { 0 };

static DEFINE_SPINLOCK(hymo_uname_lock);

/* RCU callback functions for deferred free */
static void hymo_entry_free_rcu(struct rcu_head *head)
{
    struct hymo_entry *e = container_of(head, struct hymo_entry, rcu);
    kfree(e->src);
    kfree(e->target);
    kfree(e);
}

static void hymo_hide_entry_free_rcu(struct rcu_head *head)
{
    struct hymo_hide_entry *e = container_of(head, struct hymo_hide_entry, rcu);
    kfree(e->path);
    kfree(e);
}

static void hymo_inject_entry_free_rcu(struct rcu_head *head)
{
    struct hymo_inject_entry *e = container_of(head, struct hymo_inject_entry, rcu);
    kfree(e->dir);
    kfree(e);
}

static void hymo_xattr_sb_entry_free_rcu(struct rcu_head *head)
{
    struct hymo_xattr_sb_entry *e = container_of(head, struct hymo_xattr_sb_entry, rcu);
    kfree(e);
}

static void hymo_merge_entry_free_rcu(struct rcu_head *head)
{
    struct hymo_merge_entry *e = container_of(head, struct hymo_merge_entry, rcu);
    kfree(e->src);
    kfree(e->target);
    kfree(e);
}

/* Free trie subtree (recursive); node itself is freed by caller or rcu callback */
static void hymo_merge_trie_free_node(struct hymo_merge_trie_node *n)
{
    struct hymo_merge_trie_node *c, *next;

    if (!n)
        return;
    for (c = n->first_child; c; c = next) {
        next = c->next_sibling;
        hymo_merge_trie_free_node(c);
    }
    kfree(n->comp);
    kfree(n);
}

static void hymo_merge_trie_free_rcu(struct rcu_head *head)
{
    struct hymo_merge_trie_node *root = container_of(head, struct hymo_merge_trie_node, rcu);
    hymo_merge_trie_free_node(root);
}

/* Build trie from current hymo_merge_dirs; call under hymo_merge_lock. */
static void hymo_merge_trie_build_locked(void)
{
    struct hymo_merge_trie_node *new_root;
    struct hymo_merge_trie_node *cur, **slot;
    struct hymo_merge_entry *merge_entry;
    const char *path, *start;
    char *comp;
    size_t comp_len;
    int bkt;
    struct hymo_merge_trie_node *old_root;

    spin_lock(&hymo_merge_trie_lock);
    new_root = kzalloc(sizeof(*new_root), GFP_ATOMIC);
    if (!new_root) {
        spin_unlock(&hymo_merge_trie_lock);
        return;
    }

    hash_for_each(hymo_merge_dirs, bkt, merge_entry, node) {
        if (!merge_entry->src)
            continue;
        path = merge_entry->src;
        while (*path == '/')
            path++;
        cur = new_root;
        while (*path) {
            start = path;
            while (*path && *path != '/')
                path++;
            comp_len = (size_t)(path - start);
            if (comp_len == 0) {
                if (*path)
                    path++;
                continue;
            }
            comp = kmalloc(comp_len + 1, GFP_ATOMIC);
            if (!comp)
                break;
            memcpy(comp, start, comp_len);
            comp[comp_len] = '\0';
            for (slot = &cur->first_child; *slot; slot = &(*slot)->next_sibling) {
                if ((*slot)->comp_len == comp_len && memcmp((*slot)->comp, comp, comp_len) == 0)
                    break;
            }
            if (!*slot) {
                *slot = kzalloc(sizeof(struct hymo_merge_trie_node), GFP_ATOMIC);
                if (!*slot) {
                    kfree(comp);
                    break;
                }
                (*slot)->comp = comp;
                (*slot)->comp_len = comp_len;
            } else {
                kfree(comp);
            }
            cur = *slot;
            if (*path == '/')
                path++;
        }
        cur->entry = merge_entry;
    }

    old_root = rcu_dereference_protected(hymo_merge_trie_root, lockdep_is_held(&hymo_merge_trie_lock));
    rcu_assign_pointer(hymo_merge_trie_root, new_root);
    if (old_root) {
        old_root->rcu.next = NULL;
        old_root->rcu.func = hymo_merge_trie_free_rcu;
        call_rcu(&old_root->rcu, hymo_merge_trie_free_rcu);
    }
    spin_unlock(&hymo_merge_trie_lock);
}

/* Longest-prefix lookup; call under rcu_read_lock. Returns NULL if no match. */
static struct hymo_merge_entry *hymo_merge_trie_lookup_longest(const char *pathname)
{
    struct hymo_merge_trie_node *root, *cur, *child;
    const char *path, *start;
    size_t comp_len;
    struct hymo_merge_entry *last = NULL;

    root = rcu_dereference(hymo_merge_trie_root);
    if (!root)
        return NULL;
    path = pathname;
    while (*path == '/')
        path++;
    cur = root;
    while (*path) {
        start = path;
        while (*path && *path != '/')
            path++;
        comp_len = (size_t)(path - start);
        if (comp_len == 0) {
            if (*path)
                path++;
            continue;
        }
        for (child = rcu_dereference(cur->first_child); child; child = rcu_dereference(child->next_sibling)) {
            if (child->comp_len == comp_len && memcmp(child->comp, start, comp_len) == 0)
                break;
        }
        if (!child)
            return last;
        cur = child;
        if (cur->entry)
            last = cur->entry;
        if (*path == '/')
            path++;
    }
    return last;
}

static inline void hymofs_mark_inode_hidden(struct inode *inode)
{
    if (inode && inode->i_mapping) {
        set_bit(AS_FLAGS_HYMO_HIDE, &inode->i_mapping->flags);
    }
}

static inline void hymofs_unmark_inode_hidden(struct inode *inode)
{
    if (inode && inode->i_mapping) {
        clear_bit(AS_FLAGS_HYMO_HIDE, &inode->i_mapping->flags);
    }
}

#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
bool __hymofs_is_inode_hidden(struct inode *inode)
{
    return test_bit(AS_FLAGS_HYMO_HIDE, &inode->i_mapping->flags);
}
EXPORT_SYMBOL(__hymofs_is_inode_hidden);
#endif

static void hymo_cleanup_locked(void) {
    struct hymo_entry *entry;
    struct hymo_hide_entry *hide_entry;
    struct hymo_inject_entry *inject_entry;
    struct hymo_xattr_sb_entry *sb_entry;
    struct hymo_merge_entry *merge_entry;
    struct hlist_node *tmp;
    int bkt;

    /* Mark entries for RCU deletion - actual freeing happens after grace period */
    hash_for_each_safe(hymo_paths, bkt, tmp, entry, node) {
        hlist_del_rcu(&entry->node);
        hlist_del_rcu(&entry->target_node);
        call_rcu(&entry->rcu, hymo_entry_free_rcu);
    }
    hash_for_each_safe(hymo_hide_paths, bkt, tmp, hide_entry, node) {
        hlist_del_rcu(&hide_entry->node);
        call_rcu(&hide_entry->rcu, hymo_hide_entry_free_rcu);
    }
    xa_destroy(&hymo_allow_uids_xa);
    hash_for_each_safe(hymo_inject_dirs, bkt, tmp, inject_entry, node) {
        hlist_del_rcu(&inject_entry->node);
        call_rcu(&inject_entry->rcu, hymo_inject_entry_free_rcu);
    }
    hash_for_each_safe(hymo_xattr_sbs, bkt, tmp, sb_entry, node) {
        hlist_del_rcu(&sb_entry->node);
        call_rcu(&sb_entry->rcu, hymo_xattr_sb_entry_free_rcu);
    }
    hash_for_each_safe(hymo_merge_dirs, bkt, tmp, merge_entry, node) {
        hlist_del_rcu(&merge_entry->node);
        call_rcu(&merge_entry->rcu, hymo_merge_entry_free_rcu);
    }
    {
        struct hymo_merge_trie_node *old_trie;

        spin_lock(&hymo_merge_trie_lock);
        old_trie = rcu_dereference_protected(hymo_merge_trie_root, lockdep_is_held(&hymo_merge_trie_lock));
        rcu_assign_pointer(hymo_merge_trie_root, NULL);
        if (old_trie) {
            old_trie->rcu.next = NULL;
            old_trie->rcu.func = hymo_merge_trie_free_rcu;
            call_rcu(&old_trie->rcu, hymo_merge_trie_free_rcu);
        }
        spin_unlock(&hymo_merge_trie_lock);
    }

    bitmap_zero(hymo_path_bloom, HYMO_BLOOM_SIZE);
    bitmap_zero(hymo_hide_bloom, HYMO_BLOOM_SIZE);
    atomic_set(&hymo_rule_count, 0);
    atomic_set(&hymo_hide_count, 0);
    hymo_allowlist_loaded = false;
}

/* Forward declaration for ioctl handler */
static long hymo_anon_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/* Anonymous file operations for HymoFS fd */
static const struct file_operations hymo_anon_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = hymo_anon_ioctl,
    .compat_ioctl   = hymo_anon_ioctl,
    .llseek         = noop_llseek,
};

static void hymofs_add_inject_rule(char *dir)
{
    struct hymo_inject_entry *inject_entry;
    u32 hash;
    bool found = false;

    if (!dir) return;

    hash = full_name_hash(NULL, dir, strlen(dir));
    spin_lock(&hymo_inject_lock);
    hlist_for_each_entry(inject_entry, &hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
        if (strcmp(inject_entry->dir, dir) == 0) {
            found = true;
            break;
        }
    }
    if (!found) {
        inject_entry = kmalloc(sizeof(*inject_entry), GFP_ATOMIC);
        if (inject_entry) {
            inject_entry->dir = dir;
            hlist_add_head_rcu(&inject_entry->node, &hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)]);
            atomic_inc(&hymo_rule_count);
            hymo_log("auto-inject parent: %s\n", dir);
        } else {
            kfree(dir);
        }
    } else {
        kfree(dir);
    }
    spin_unlock(&hymo_inject_lock);
}

static void hymofs_reorder_mnt_id(void)
{
    struct mnt_namespace *ns = current->nsproxy->mnt_ns;
    struct mount *m;
    int id = 1;
    bool is_hymo_mount;

    if (!ns) return;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0))
    /* 6.12+: ns->mounts is rb_root */
    struct mount *n;
    if (ns->mounts.rb_node) {
        struct rb_node *first_node = rb_first(&ns->mounts);
        if (first_node) {
            struct mount *first = rb_entry(first_node, struct mount, mnt_node);
            if (first->mnt_id < 500000)
                id = first->mnt_id;
        }
    }
    rbtree_postorder_for_each_entry_safe(m, n, &ns->mounts, mnt_node) {
#else
    if (!list_empty(&ns->list)) {
        struct mount *first = list_first_entry(&ns->list, struct mount, mnt_list);
        if (first->mnt_id < 500000)
            id = first->mnt_id;
    }
    list_for_each_entry(m, &ns->list, mnt_list) {
#endif
        is_hymo_mount = false;

        if (m->mnt_devname && (
            strcmp(m->mnt_devname, hymo_current_mirror_path) == 0 ||
            strcmp(m->mnt_devname, hymo_current_mirror_name) == 0
        )) {
            is_hymo_mount = true;
        }

        if (is_hymo_mount && hymo_stealth_enabled) {
            if (m->mnt_id < 500000) {
                WRITE_ONCE(m->mnt_id, 500000 + (id % 1000));
            }
        } else {
            if (m->mnt_id >= 500000) continue;
            WRITE_ONCE(m->mnt_id, id++);
        }
    }
}

static void hymofs_spoof_mounts(void)
{
    struct mnt_namespace *ns = current->nsproxy->mnt_ns;
    struct mount *m;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0))
    struct mount *n;
#endif
    char *system_devname = NULL;
    struct path sys_path;

    if (!ns) return;
    if (!hymo_stealth_enabled) return;

    if (kern_path("/system", LOOKUP_FOLLOW, &sys_path) == 0) {
        struct mount *sys_mnt = real_mount(sys_path.mnt);
        if (sys_mnt && sys_mnt->mnt_devname) {
            system_devname = kstrdup(sys_mnt->mnt_devname, GFP_KERNEL);
        }
        path_put(&sys_path);
    }
    
    if (!system_devname) {
        if (kern_path("/", LOOKUP_FOLLOW, &sys_path) == 0) {
            struct mount *sys_mnt = real_mount(sys_path.mnt);
            if (sys_mnt && sys_mnt->mnt_devname) {
                system_devname = kstrdup(sys_mnt->mnt_devname, GFP_KERNEL);
            }
            path_put(&sys_path);
        }
    }

    if (!system_devname) return;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0))
    rbtree_postorder_for_each_entry_safe(m, n, &ns->mounts, mnt_node) {
#else
    list_for_each_entry(m, &ns->list, mnt_list) {
#endif
        if (m->mnt_devname && (
            strcmp(m->mnt_devname, hymo_current_mirror_path) == 0 ||
            strcmp(m->mnt_devname, hymo_current_mirror_name) == 0
        )) {
            const char *old_name = m->mnt_devname;
            m->mnt_devname = kstrdup(system_devname, GFP_KERNEL);
            if (m->mnt_devname) {
                kfree_const(old_name);
            } else {
                m->mnt_devname = old_name;
            }
        }
    }
    kfree(system_devname);
}

int hymo_dispatch_cmd(unsigned int cmd, void __user *arg) {
    struct hymo_syscall_arg req;
    struct hymo_entry *entry;
    struct hymo_hide_entry *hide_entry;
    struct hymo_inject_entry *inject_entry;
    char *src = NULL, *target = NULL;
    u32 hash;
    bool found = false;
    int ret = 0;

    if (cmd == HYMO_CMD_CLEAR_ALL) {
        spin_lock(&hymo_cfg_lock);
        spin_lock(&hymo_rules_lock);
        spin_lock(&hymo_hide_lock);
        spin_lock(&hymo_allow_uids_lock);
        spin_lock(&hymo_xattr_sbs_lock);
        spin_lock(&hymo_merge_lock);
        spin_lock(&hymo_inject_lock);
        hymo_cleanup_locked();
        strscpy(hymo_mirror_path_buf, HYMO_DEFAULT_MIRROR_PATH, PATH_MAX);
        strscpy(hymo_mirror_name_buf, HYMO_DEFAULT_MIRROR_NAME, NAME_MAX);
        hymo_current_mirror_path = hymo_mirror_path_buf;
        hymo_current_mirror_name = hymo_mirror_name_buf;
        spin_unlock(&hymo_inject_lock);
        spin_unlock(&hymo_merge_lock);
        spin_unlock(&hymo_xattr_sbs_lock);
        spin_unlock(&hymo_allow_uids_lock);
        spin_unlock(&hymo_hide_lock);
        spin_unlock(&hymo_rules_lock);
        spin_unlock(&hymo_cfg_lock);
        rcu_barrier();
        return 0;
    }
    
    if (cmd == HYMO_CMD_GET_VERSION) {
        return HYMO_PROTOCOL_VERSION;
    }

    if (cmd == HYMO_CMD_SET_DEBUG) {
        int val;
        if (copy_from_user(&val, arg, sizeof(val))) return -EFAULT;
        hymo_debug_enabled = !!val;
        hymo_log("debug mode %s\n", hymo_debug_enabled ? "enabled" : "disabled");
        return 0;
    }

    if (cmd == HYMO_CMD_REORDER_MNT_ID) {
        hymofs_spoof_mounts();
        hymofs_reorder_mnt_id();
        return 0;
    }

    if (cmd == HYMO_CMD_SET_STEALTH) {
        int val;
        if (copy_from_user(&val, arg, sizeof(val))) return -EFAULT;
        hymo_stealth_enabled = !!val;
        hymo_log("stealth mode %s\n", hymo_stealth_enabled ? "enabled" : "disabled");
        if (hymo_stealth_enabled) {
            hymofs_spoof_mounts();
            hymofs_reorder_mnt_id();
        }
        return 0;
    }

    if (cmd == HYMO_CMD_SET_ENABLED) {
        int val;
        if (copy_from_user(&val, arg, sizeof(val))) return -EFAULT;
        spin_lock(&hymo_cfg_lock);
        hymofs_enabled = !!val;
        spin_unlock(&hymo_cfg_lock);
        hymo_log("HymoFS %s\n", hymofs_enabled ? "enabled" : "disabled");
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
        if (hymofs_enabled) {
            hymo_reload_ksu_allowlist();
        }
#endif
        return 0;
    }

    if (cmd == HYMO_CMD_GET_FD) {
        /* Return anonymous fd - the ONLY way to access HymoFS */
        int fd;
        pid_t pid;
        if (!uid_eq(current_uid(), GLOBAL_ROOT_UID)) {
            return -EPERM;
        }
        fd = anon_inode_getfd("hymo", &hymo_anon_fops, NULL, O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            return fd;
        }
        
        /* Automatically register this process as the daemon */
        pid = task_tgid_vnr(current);
        spin_lock(&hymo_daemon_lock);
        hymo_daemon_pid = pid;
        spin_unlock(&hymo_daemon_lock);
        hymo_log("Daemon PID auto-registered: %d\n", pid);
        
        return fd;  /* Return fd directly */
    }

    /* LIST_RULES uses a different struct, handle it separately */
    if (cmd == HYMO_CMD_LIST_RULES) {
        struct hymo_syscall_list_arg list_arg;
        char *kbuf;
        size_t buf_size;
        size_t written = 0;
        int bkt;
        struct hymo_xattr_sb_entry *sb_entry;
        struct hymo_merge_entry *merge_entry;

        if (copy_from_user(&list_arg, (void __user *)arg, sizeof(list_arg))) {
            return -EFAULT;
        }

        buf_size = list_arg.size;
        if (buf_size > 16 * 1024) buf_size = 16 * 1024;
        
        kbuf = kzalloc(buf_size, GFP_KERNEL);
        if (!kbuf) {
            return -ENOMEM;
        }

        rcu_read_lock();
        
        written += scnprintf(kbuf + written, buf_size - written, "HymoFS Protocol: %d\n", HYMO_PROTOCOL_VERSION);
        written += scnprintf(kbuf + written, buf_size - written, "HymoFS Enabled: %d\n", hymofs_enabled ? 1 : 0);

        hash_for_each_rcu(hymo_paths, bkt, entry, node) {
            if (written >= buf_size) break;
            written += scnprintf(kbuf + written, buf_size - written, "add %s %s %d\n", entry->src, entry->target, entry->type);
        }
        hash_for_each_rcu(hymo_hide_paths, bkt, hide_entry, node) {
            if (written >= buf_size) break;
            written += scnprintf(kbuf + written, buf_size - written, "hide %s\n", hide_entry->path);
        }
        hash_for_each_rcu(hymo_inject_dirs, bkt, inject_entry, node) {
            if (written >= buf_size) break;
            written += scnprintf(kbuf + written, buf_size - written, "inject %s\n", inject_entry->dir);
        }
        hash_for_each_rcu(hymo_merge_dirs, bkt, merge_entry, node) {
            if (written >= buf_size) break;
            written += scnprintf(kbuf + written, buf_size - written, "merge %s %s\n", merge_entry->src, merge_entry->target);
        }
        hash_for_each_rcu(hymo_xattr_sbs, bkt, sb_entry, node) {
            if (written >= buf_size) break;
            written += scnprintf(kbuf + written, buf_size - written, "hide_xattr_sb %p\n", sb_entry->sb);
        }
        rcu_read_unlock();

        if (copy_to_user(list_arg.buf, kbuf, written)) {
            kfree(kbuf);
            return -EFAULT;
        }
        list_arg.size = written;
        if (copy_to_user((void __user *)arg, &list_arg, sizeof(list_arg))) {
            kfree(kbuf);
            return -EFAULT;
        }
        
        kfree(kbuf);
        return 0;
    }

    if (cmd == HYMO_CMD_SET_UNAME) {
#ifdef CONFIG_HYMOFS_UNAME_SPOOF
        struct hymo_uname_info u_info;

        if (copy_from_user(&u_info, arg, sizeof(u_info)))
            return -EFAULT;

        spin_lock(&hymo_uname_lock);
        memcpy(&hymo_uname_info, &u_info, sizeof(u_info));
        spin_unlock(&hymo_uname_lock);
        return 0;
#else
        return -EOPNOTSUPP;
#endif
    }

    if (copy_from_user(&req, arg, sizeof(req))) return -EFAULT;

    if (cmd == HYMO_CMD_SET_MIRROR_PATH) {
        char *new_path = NULL;
        char *new_name = NULL;
        char *slash;
        size_t len;

        if (req.src) {
            new_path = strndup_user(req.src, PATH_MAX);
            if (IS_ERR(new_path)) return PTR_ERR(new_path);
        } else {
            return -EINVAL;
        }

        hymo_log("setting mirror path to: %s\n", new_path);

        /* Strip trailing slash if present */
        len = strlen(new_path);
        if (len > 1 && new_path[len - 1] == '/') {
            new_path[len - 1] = '\0';
        }

        slash = strrchr(new_path, '/');
        if (slash) {
            new_name = kstrdup(slash + 1, GFP_KERNEL);
        } else {
            new_name = kstrdup(new_path, GFP_KERNEL);
        }

        if (!new_name) {
            kfree(new_path);
            return -ENOMEM;
        }

        spin_lock(&hymo_cfg_lock);
        strscpy(hymo_mirror_path_buf, new_path, PATH_MAX);
        strscpy(hymo_mirror_name_buf, new_name, NAME_MAX);
        hymo_current_mirror_path = hymo_mirror_path_buf;
        hymo_current_mirror_name = hymo_mirror_name_buf;
        spin_unlock(&hymo_cfg_lock);

        kfree(new_path);
        kfree(new_name);
        return 0;
    }

    if (req.src) {
        src = strndup_user(req.src, PAGE_SIZE);
        if (IS_ERR(src)) return PTR_ERR(src);
    }
    if (req.target) {
        target = strndup_user(req.target, PAGE_SIZE);
        if (IS_ERR(target)) {
            kfree(src);
            return PTR_ERR(target);
        }
    }

    switch (cmd) {
        case HYMO_CMD_ADD_MERGE_RULE: {
            struct hymo_merge_entry *merge_entry;
            if (!src || !target) { ret = -EINVAL; break; }
            
            hymo_log("add merge rule: src=%s, target=%s\n", src, target);
            
            hash = full_name_hash(NULL, src, strlen(src));
            spin_lock(&hymo_merge_lock);
            spin_lock(&hymo_inject_lock);
            
            hlist_for_each_entry(merge_entry, &hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
                if (strcmp(merge_entry->src, src) == 0 && strcmp(merge_entry->target, target) == 0) {
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                merge_entry = kmalloc(sizeof(*merge_entry), GFP_ATOMIC);
                if (merge_entry) {
                    merge_entry->src = src;
                    merge_entry->target = target;
                    hlist_add_head_rcu(&merge_entry->node, &hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)]);
                    
                    {
                        struct hymo_inject_entry *inj;
                        bool inj_found = false;
                        hlist_for_each_entry(inj, &hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
                            if (strcmp(inj->dir, src) == 0) {
                                inj_found = true;
                                break;
                            }
                        }
                        if (!inj_found) {
                            inj = kmalloc(sizeof(*inj), GFP_ATOMIC);
                            if (inj) {
                                inj->dir = kstrdup(src, GFP_ATOMIC);
                                if (inj->dir) hlist_add_head_rcu(&inj->node, &hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)]);
                                else kfree(inj);
                            }
                        }
                    }
                    
                    src = NULL;
                    target = NULL;
                    hymo_merge_trie_build_locked();
                } else {
                    ret = -ENOMEM;
                }
            } else {
                ret = -EEXIST;
            }
            spin_unlock(&hymo_inject_lock);
            spin_unlock(&hymo_merge_lock);
            if (!found && merge_entry)
                hymofs_add_inject_rule(kstrdup(merge_entry->src, GFP_ATOMIC));
            spin_lock(&hymo_cfg_lock);
            hymofs_enabled = true;
            spin_unlock(&hymo_cfg_lock);
            break;
        }

        case HYMO_CMD_ADD_RULE: {
            char *parent_dir = NULL;
            char *resolved_src = NULL;
            struct path path;
            struct inode *src_inode = NULL;
            struct inode *parent_inode = NULL;
            char *tmp_buf = kmalloc(PATH_MAX, GFP_KERNEL);
            
            if (!src || !target) { 
                kfree(tmp_buf);
                ret = -EINVAL; 
                break; 
            }
            if (!tmp_buf) { ret = -ENOMEM; break; }

            hymo_log("add rule: src=%s, target=%s, type=%d\n", src, target, req.type);
            
            // 1. Try to resolve full path (if file exists)
            if (kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
                char *res = d_path(&path, tmp_buf, PATH_MAX);
                if (!IS_ERR(res)) {
                    resolved_src = kstrdup(res, GFP_KERNEL);
                    
                    /* Always extract parent directory for injection, even if file exists */
                    {
                        char *last_slash = strrchr(res, '/');
                        if (last_slash) {
                            if (last_slash == res) {
                                parent_dir = kstrdup("/", GFP_KERNEL);
                            } else {
                                size_t len = last_slash - res;
                                parent_dir = kmalloc(len + 1, GFP_KERNEL);
                                if (parent_dir) {
                                    memcpy(parent_dir, res, len);
                                    parent_dir[len] = '\0';
                                }
                            }
                        }
                    }
                }
                /* Get inode reference for marking (hide source in filldir) */
                if (d_inode(path.dentry)) {
                    src_inode = d_inode(path.dentry);
                    ihold(src_inode);
                }
                if (path.dentry->d_parent && d_inode(path.dentry->d_parent)) {
                    parent_inode = d_inode(path.dentry->d_parent);
                    ihold(parent_inode);
                }
                path_put(&path);
            } else {
                char *last_slash = strrchr(src, '/');
                if (last_slash && last_slash != src) {
                    size_t len = last_slash - src;
                    char *p_str = kmalloc(len + 1, GFP_KERNEL);
                    if (p_str) {
                        memcpy(p_str, src, len);
                        p_str[len] = '\0';
                        
                        if (kern_path(p_str, LOOKUP_FOLLOW, &path) == 0) {
                            char *res = d_path(&path, tmp_buf, PATH_MAX);
                            if (!IS_ERR(res)) {
                                size_t res_len = strlen(res);
                                size_t name_len = strlen(last_slash);
                                resolved_src = kmalloc(res_len + name_len + 1, GFP_KERNEL);
                                if (resolved_src) {
                                    strcpy(resolved_src, res);
                                    strcat(resolved_src, last_slash);
                                }
                                parent_dir = kstrdup(res, GFP_KERNEL);
                            }
                            path_put(&path);
                        }
                        kfree(p_str);
                    }
                }
            }
            
            kfree(tmp_buf);

            if (resolved_src) {
                kfree(src);
                src = resolved_src;
            }

            hash = full_name_hash(NULL, src, strlen(src));
            spin_lock(&hymo_rules_lock);

            {
                hlist_for_each_entry(entry, &hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
                    if (entry->src_hash == hash && strcmp(entry->src, src) == 0) {
                        /* Update existing entry - need RCU-safe update */
                        char *old_target = entry->target;
                        char *new_target = kstrdup(target, GFP_ATOMIC);
                        if (new_target) {
                            hlist_del_rcu(&entry->target_node);
                            rcu_assign_pointer(entry->target, new_target);
                            entry->type = req.type;
                            hlist_add_head_rcu(&entry->target_node, &hymo_targets[hash_min(full_name_hash(NULL, new_target, strlen(new_target)), HYMO_HASH_BITS)]);
                            /* Free old target after grace period - use kfree_rcu if available, else synchronize */
                            kfree(old_target);
                        }
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
                    if (entry) {
                        entry->src = kstrdup(src, GFP_ATOMIC);
                        entry->target = kstrdup(target, GFP_ATOMIC);
                        entry->type = req.type;
                        entry->src_hash = hash;
                        if (entry->src && entry->target) {
                            unsigned long h1, h2;
                            hlist_add_head_rcu(&entry->node, &hymo_paths[hash_min(hash, HYMO_HASH_BITS)]);
                            hlist_add_head_rcu(&entry->target_node, &hymo_targets[hash_min(full_name_hash(NULL, entry->target, strlen(entry->target)), HYMO_HASH_BITS)]);
                            
                            h1 = jhash(src, strlen(src), 0) & (HYMO_BLOOM_SIZE - 1);
                            h2 = jhash(src, strlen(src), 1) & (HYMO_BLOOM_SIZE - 1);
                            set_bit(h1, hymo_path_bloom);
                            set_bit(h2, hymo_path_bloom);
                            atomic_inc(&hymo_rule_count);
                        } else {
                            kfree(entry->src);
                            kfree(entry->target);
                            kfree(entry);
                        }
                    }
                }
            }

            spin_unlock(&hymo_rules_lock);
            if (parent_dir) {
                hymofs_add_inject_rule(parent_dir);
            }

            if (src_inode) {
                hymofs_mark_inode_hidden(src_inode);
                iput(src_inode);
            }

            if (parent_inode) {
                if (parent_inode->i_mapping) {
                    set_bit(AS_FLAGS_HYMO_DIR_HAS_HIDDEN, &parent_inode->i_mapping->flags);
                }
                iput(parent_inode);
            }

            spin_lock(&hymo_cfg_lock);
            hymofs_enabled = true;
            spin_unlock(&hymo_cfg_lock);
            break;
        }

        case HYMO_CMD_HIDE_RULE: {
            char *resolved_src = NULL;
            struct path path;
            struct inode *target_inode = NULL;
            struct inode *parent_inode = NULL;
            char *tmp_buf = kmalloc(PATH_MAX, GFP_KERNEL);

            if (!src) { 
                kfree(tmp_buf);
                ret = -EINVAL; 
                break; 
            }
            if (!tmp_buf) { ret = -ENOMEM; break; }

            hymo_log("hide rule: src=%s\n", src);

            if (kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
                char *res = d_path(&path, tmp_buf, PATH_MAX);
                if (!IS_ERR(res)) {
                    resolved_src = kstrdup(res, GFP_KERNEL);
                }
                /* Get inode reference for marking */
                if (d_inode(path.dentry)) {
                    target_inode = d_inode(path.dentry);
                    ihold(target_inode);  /* Hold reference */
                }
                /* Also get parent directory inode */
                if (path.dentry->d_parent && d_inode(path.dentry->d_parent)) {
                    parent_inode = d_inode(path.dentry->d_parent);
                    ihold(parent_inode);
                }
                path_put(&path);
            }
            kfree(tmp_buf);

            if (resolved_src) {
                kfree(src);
                src = resolved_src;
            }

            if (target_inode) {
                hymofs_mark_inode_hidden(target_inode);
                iput(target_inode);
            }

            if (parent_inode) {
                if (parent_inode->i_mapping) {
                    set_bit(AS_FLAGS_HYMO_DIR_HAS_HIDDEN, &parent_inode->i_mapping->flags);
                }
                iput(parent_inode);
            }

            hash = full_name_hash(NULL, src, strlen(src));
            spin_lock(&hymo_hide_lock);
            hlist_for_each_entry(hide_entry, &hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
                if (hide_entry->path_hash == hash && strcmp(hide_entry->path, src) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                hide_entry = kmalloc(sizeof(*hide_entry), GFP_ATOMIC);
                if (hide_entry) {
                    hide_entry->path = kstrdup(src, GFP_ATOMIC);
                    hide_entry->path_hash = hash;
                    if (hide_entry->path) {
                        unsigned long h1 = jhash(src, strlen(src), 0) & (HYMO_BLOOM_SIZE - 1);
                        unsigned long h2 = jhash(src, strlen(src), 1) & (HYMO_BLOOM_SIZE - 1);
                        set_bit(h1, hymo_hide_bloom);
                        set_bit(h2, hymo_hide_bloom);
                        atomic_inc(&hymo_hide_count);
                        hlist_add_head_rcu(&hide_entry->node, &hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)]);
                    } else {
                        kfree(hide_entry);
                    }
                }
            }
            spin_unlock(&hymo_hide_lock);
            spin_lock(&hymo_cfg_lock);
            hymofs_enabled = true;
            spin_unlock(&hymo_cfg_lock);
            break;
        }

        case HYMO_CMD_HIDE_OVERLAY_XATTRS: {
            struct path path;
            struct hymo_xattr_sb_entry *sb_entry;
            bool found = false;
            
            if (!src) { ret = -EINVAL; break; }
            
            if (kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
                struct super_block *sb = path.dentry->d_sb;
                
                spin_lock(&hymo_xattr_sbs_lock);
                hlist_for_each_entry(sb_entry, &hymo_xattr_sbs[hash_min((unsigned long)sb, HYMO_HASH_BITS)], node) {
                    if (sb_entry->sb == sb) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    sb_entry = kmalloc(sizeof(*sb_entry), GFP_ATOMIC);
                    if (sb_entry) {
                        sb_entry->sb = sb;
                        hlist_add_head_rcu(&sb_entry->node, &hymo_xattr_sbs[hash_min((unsigned long)sb, HYMO_HASH_BITS)]);
                        hymo_log("hide xattrs for sb %p (path: %s)\n", sb, src);
                    }
                }
                spin_unlock(&hymo_xattr_sbs_lock);
                spin_lock(&hymo_cfg_lock);
                hymofs_enabled = true;
                spin_unlock(&hymo_cfg_lock);
                path_put(&path);
            } else {
                ret = -ENOENT;
            }
            break;
        }

        case HYMO_CMD_DEL_RULE:
            if (!src) { ret = -EINVAL; break; }
            hymo_log("del rule: src=%s\n", src);
            hash = full_name_hash(NULL, src, strlen(src));
            spin_lock(&hymo_rules_lock);
            spin_lock(&hymo_hide_lock);
            spin_lock(&hymo_inject_lock);
            
            hlist_for_each_entry(entry, &hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
                if (entry->src_hash == hash && strcmp(entry->src, src) == 0) {
                    hlist_del_rcu(&entry->node);
                    hlist_del_rcu(&entry->target_node);
                    atomic_dec(&hymo_rule_count);
                    call_rcu(&entry->rcu, hymo_entry_free_rcu);
                    goto out_delete;
                }
            }
            hlist_for_each_entry(hide_entry, &hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
                if (hide_entry->path_hash == hash && strcmp(hide_entry->path, src) == 0) {
                    hlist_del_rcu(&hide_entry->node);
                    atomic_dec(&hymo_hide_count);
                    call_rcu(&hide_entry->rcu, hymo_hide_entry_free_rcu);
                    goto out_delete;
                }
            }
            hlist_for_each_entry(inject_entry, &hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
                if (strcmp(inject_entry->dir, src) == 0) {
                    hlist_del_rcu(&inject_entry->node);
                    atomic_dec(&hymo_rule_count);
                    call_rcu(&inject_entry->rcu, hymo_inject_entry_free_rcu);
                    goto out_delete;
                }
            }
    out_delete:
            spin_unlock(&hymo_inject_lock);
            spin_unlock(&hymo_hide_lock);
            spin_unlock(&hymo_rules_lock);
            spin_lock(&hymo_cfg_lock);
            hymofs_enabled = true;
            spin_unlock(&hymo_cfg_lock);
            break;

        case HYMO_CMD_REORDER_MNT_ID:
            hymo_log("reordering mount IDs\n");
            hymofs_reorder_mnt_id();
            break;

        default:
            ret = -EINVAL;
            break;
    }

    kfree(src);
    kfree(target);
    return ret;
}

static long hymo_anon_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    /* All ioctl commands directly dispatch to hymo_dispatch_cmd */
    if (cmd == HYMO_IOC_GET_VERSION) {
        int version = HYMO_PROTOCOL_VERSION;
        if (copy_to_user((void __user *)arg, &version, sizeof(version)))
            return -EFAULT;
        return 0;
    }

    if (cmd == HYMO_IOC_SET_ENABLED) {
        int enabled;
        if (copy_from_user(&enabled, (void __user *)arg, sizeof(enabled)))
            return -EFAULT;
        spin_lock(&hymo_cfg_lock);
        hymofs_enabled = enabled ? true : false;
        spin_unlock(&hymo_cfg_lock);
#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
        if (hymofs_enabled) {
            hymo_reload_ksu_allowlist();
        }
#endif
        return 0;
    }

    /* Map ioctl to internal command and dispatch */
    switch (cmd) {
    case HYMO_IOC_ADD_RULE:
        return hymo_dispatch_cmd(HYMO_CMD_ADD_RULE, (void __user *)arg);
    case HYMO_IOC_DEL_RULE:
        return hymo_dispatch_cmd(HYMO_CMD_DEL_RULE, (void __user *)arg);
    case HYMO_IOC_HIDE_RULE:
        return hymo_dispatch_cmd(HYMO_CMD_HIDE_RULE, (void __user *)arg);
    case HYMO_IOC_CLEAR_ALL:
        return hymo_dispatch_cmd(HYMO_CMD_CLEAR_ALL, (void __user *)arg);
    case HYMO_IOC_LIST_RULES:
        return hymo_dispatch_cmd(HYMO_CMD_LIST_RULES, (void __user *)arg);
    case HYMO_IOC_SET_DEBUG:
        return hymo_dispatch_cmd(HYMO_CMD_SET_DEBUG, (void __user *)arg);
    case HYMO_IOC_REORDER_MNT_ID:
        return hymo_dispatch_cmd(HYMO_CMD_REORDER_MNT_ID, (void __user *)arg);
    case HYMO_IOC_SET_STEALTH:
        return hymo_dispatch_cmd(HYMO_CMD_SET_STEALTH, (void __user *)arg);
    case HYMO_IOC_HIDE_OVERLAY_XATTRS:
        return hymo_dispatch_cmd(HYMO_CMD_HIDE_OVERLAY_XATTRS, (void __user *)arg);
    case HYMO_IOC_ADD_MERGE_RULE:
        return hymo_dispatch_cmd(HYMO_CMD_ADD_MERGE_RULE, (void __user *)arg);
    case HYMO_IOC_SET_MIRROR_PATH:
        return hymo_dispatch_cmd(HYMO_CMD_SET_MIRROR_PATH, (void __user *)arg);
    case HYMO_IOC_SET_UNAME:
        return hymo_dispatch_cmd(HYMO_CMD_SET_UNAME, (void __user *)arg);
    default:
        return -EINVAL;
    }
}

static int __init hymofs_init(void)
{
    hash_init(hymo_paths);
    hash_init(hymo_targets);
    hash_init(hymo_hide_paths);
    /* hymo_allow_uids_xa is statically defined, starts empty */
    hash_init(hymo_inject_dirs);
    hash_init(hymo_xattr_sbs);
    
    if (hymo_dispatch_cmd_hook) {
        pr_err("HymoFS: hook already set?\n");
    } else {
        hymo_dispatch_cmd_hook = hymo_dispatch_cmd;
    }
    
    pr_info("HymoFS: initialized (Anonymous FD Mode Only)\n");
    return 0;
}
fs_initcall(hymofs_init);

#ifdef CONFIG_HYMOFS_FORWARD_REDIRECT
char *__hymofs_resolve_target(const char *pathname)
{
    struct hymo_entry *entry;
    struct hymo_merge_entry *merge_entry;
    u32 hash;
    char *target = NULL;
    size_t path_len;
    struct list_head candidates;
    struct hymo_merge_target_node *cand, *tmp;
    pid_t current_pid;

    if (unlikely(!hymofs_enabled)) return NULL;
    if (unlikely(!pathname)) return NULL;
    
    /* Allow daemon process to bypass path resolution */
    current_pid = task_tgid_vnr(current);
    if (hymo_daemon_pid > 0 && current_pid == hymo_daemon_pid) {
        return NULL;
    }
    
    INIT_LIST_HEAD(&candidates);
    path_len = strlen(pathname);
    hash = full_name_hash(NULL, pathname, path_len);

    rcu_read_lock();
    /* Bloom filter fast-path: skip expensive path lookup when path is definitely not in rules (KPM backport) */
    if (atomic_read(&hymo_rule_count) != 0) {
        unsigned long bh1 = jhash(pathname, (u32)path_len, 0) & (HYMO_BLOOM_SIZE - 1);
        unsigned long bh2 = jhash(pathname, (u32)path_len, 1) & (HYMO_BLOOM_SIZE - 1);
        if (test_bit(bh1, hymo_path_bloom) && test_bit(bh2, hymo_path_bloom)) {
            hlist_for_each_entry_rcu(entry, &hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
                if (unlikely(entry->src_hash == hash && strcmp(entry->src, pathname) == 0)) {
                    target = kstrdup(entry->target, GFP_ATOMIC);
                    rcu_read_unlock();
                    return target;
                }
            }
        }
    }
    
    /* Longest-prefix merge match via trie (one path walk instead of O(depth) hash lookups) */
    merge_entry = hymo_merge_trie_lookup_longest(pathname);
    if (merge_entry) {
        size_t src_len = strlen(merge_entry->src);
        const char *suffix = pathname + src_len;

        if (suffix[0] != '\0' && strcmp(suffix, "/.") != 0 && strcmp(suffix, "/..") != 0) {
            size_t target_len = strlen(merge_entry->target);
            size_t suffix_len = path_len - src_len;

            cand = kmalloc(sizeof(*cand), GFP_ATOMIC);
            if (cand) {
                cand->target = kmalloc(target_len + suffix_len + 1, GFP_ATOMIC);
                if (cand->target) {
                    strcpy(cand->target, merge_entry->target);
                    strcat(cand->target, suffix);
                    list_add_tail(&cand->list, &candidates);
                } else {
                    kfree(cand);
                }
            }
        }
    }

    rcu_read_unlock();
    
    list_for_each_entry_safe(cand, tmp, &candidates, list) {
        if (!target) {
            struct path p;
            if (kern_path(cand->target, LOOKUP_FOLLOW, &p) == 0) {
                path_put(&p);
                target = cand->target; // Take ownership
                cand->target = NULL;   // Prevent double free
            }
        }
        
        if (cand->target) kfree(cand->target);
        kfree(cand);
    }

    return target;
}
EXPORT_SYMBOL(__hymofs_resolve_target);

#endif /* CONFIG_HYMOFS_FORWARD_REDIRECT */

#ifdef CONFIG_HYMOFS_REVERSE_LOOKUP
/* Returns length of written string, or -1 if not found/error. Writes to buf. */
int __hymofs_reverse_lookup(const char *pathname, char *buf, size_t buflen)
{
    struct hymo_entry *entry;
    struct hymo_merge_entry *merge_entry;
    u32 hash;
    int bkt;
    int ret = -1;

    if (unlikely(!hymofs_enabled)) return -1;
    if (unlikely(!pathname || !buf)) return -1;

    hash = full_name_hash(NULL, pathname, strlen(pathname));

    rcu_read_lock();
    
    /* Check 1-to-1 mappings */
    hlist_for_each_entry_rcu(entry, &hymo_targets[hash_min(hash, HYMO_HASH_BITS)], target_node) {
        if (strcmp(entry->target, pathname) == 0) {
            if (strscpy(buf, entry->src, buflen) < 0) ret = -ENAMETOOLONG;
            else ret = strlen(buf);
            goto out;
        }
    }

    hash_for_each_rcu(hymo_merge_dirs, bkt, merge_entry, node) {
        size_t target_len = strlen(merge_entry->target);
        if (strncmp(pathname, merge_entry->target, target_len) == 0) {
            if (pathname[target_len] == '/' || pathname[target_len] == '\0') {
                size_t src_len = strlen(merge_entry->src);
                size_t suffix_len = strlen(pathname) - target_len;
                
                if (src_len + suffix_len + 1 > buflen) {
                    ret = -ENAMETOOLONG;
                } else {
                    memcpy(buf, merge_entry->src, src_len);
                    memcpy(buf + src_len, pathname + target_len, suffix_len);
                    buf[src_len + suffix_len] = '\0';
                    ret = src_len + suffix_len;
        }
                goto out;
    }
        }
    }

out:
    rcu_read_unlock();
    return ret;
}
EXPORT_SYMBOL(__hymofs_reverse_lookup);
#endif /* CONFIG_HYMOFS_REVERSE_LOOKUP */

#ifdef CONFIG_HYMOFS_HIDE_ENTRIES
static inline bool hymo_is_privileged_process(void)
{
    pid_t current_pid = task_tgid_vnr(current);
    if (unlikely(uid_eq(current_uid(), GLOBAL_ROOT_UID)))
        return true;
    if (hymo_daemon_pid > 0 && current_pid == hymo_daemon_pid)
        return true;
    return false;
}

static bool hymo_should_umount_profile(const struct hymo_app_profile *profile)
{
    if (profile->allow_su)
        return false;
    if (profile->nrp_config.use_default)
        return true;
    return profile->nrp_config.profile.umount_modules;
}

static void hymo_clear_allowlist_locked(void)
{
    xa_destroy(&hymo_allow_uids_xa);
}

static void hymo_add_allow_uid(uid_t uid)
{
    spin_lock(&hymo_allow_uids_lock);
    xa_store(&hymo_allow_uids_xa, uid, HYMO_UID_ALLOW_MARKER, GFP_KERNEL);
    spin_unlock(&hymo_allow_uids_lock);
}

static bool hymo_reload_ksu_allowlist(void)
{
    struct file *fp;
    loff_t off = 0;
    u32 magic = 0;
    u32 version = 0;
    ssize_t ret;
    struct hymo_app_profile profile;
    int allow_count = 0;

    if (!mutex_trylock(&hymo_allowlist_lock))
        return false;

    fp = filp_open(HYMO_KSU_ALLOWLIST_PATH, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        spin_lock(&hymo_allow_uids_lock);
        hymo_clear_allowlist_locked();
        hymo_allowlist_loaded = false;
        spin_unlock(&hymo_allow_uids_lock);
        mutex_unlock(&hymo_allowlist_lock);
        return false;
    }

    ret = kernel_read(fp, &magic, sizeof(magic), &off);
    if (ret != sizeof(magic) || magic != HYMO_KSU_ALLOWLIST_MAGIC)
        goto out_bad;

    ret = kernel_read(fp, &version, sizeof(version), &off);
    if (ret != sizeof(version))
        goto out_bad;
    if (version != HYMO_KSU_ALLOWLIST_VERSION)
        hymo_log("allowlist version %u\n", version);

    spin_lock(&hymo_allow_uids_lock);
    hymo_clear_allowlist_locked();
    hymo_allowlist_loaded = true;
    spin_unlock(&hymo_allow_uids_lock);

    while (kernel_read(fp, &profile, sizeof(profile), &off) == sizeof(profile)) {
        if (!hymo_should_umount_profile(&profile)) {
            if (profile.current_uid > 0) {
                hymo_add_allow_uid((uid_t)profile.current_uid);
                if (++allow_count >= HYMO_ALLOWLIST_UID_MAX) {
                    hymo_log("allowlist truncated at %d\n", allow_count);
                    break;
                }
            }
        }
    }

    filp_close(fp, NULL);
    mutex_unlock(&hymo_allowlist_lock);
    return true;

out_bad:
    filp_close(fp, NULL);
    spin_lock(&hymo_allow_uids_lock);
    hymo_clear_allowlist_locked();
    hymo_allowlist_loaded = false;
    spin_unlock(&hymo_allow_uids_lock);
    mutex_unlock(&hymo_allowlist_lock);
    return false;
}

static bool hymo_uid_in_allowlist(uid_t uid)
{
    void *p;

    rcu_read_lock();
    p = xa_load(&hymo_allow_uids_xa, uid);
    rcu_read_unlock();
    return p != NULL;
}

static bool hymo_should_apply_hide_rules(void)
{
    if (!hymo_allowlist_loaded)
        return true;

    /* Empty allowlist means hide for all non-privileged processes */
    if (xa_empty(&hymo_allow_uids_xa))
        return true;

    /* Allowlist mode: listed UIDs bypass hide rules */
    return !hymo_uid_in_allowlist(__kuid_val(current_uid()));
}

bool __hymofs_should_hide(const char *pathname, size_t len)
{
    struct hymo_hide_entry *hide_entry;
    u32 hash;

    if (unlikely(!hymofs_enabled)) return false;
    if (unlikely(!pathname)) return false;

    if (unlikely(hymo_is_privileged_process())) return false;

    if (likely(hymo_stealth_enabled)) {
        size_t name_len = strlen(hymo_current_mirror_name);
        size_t path_len = strlen(hymo_current_mirror_path);

        if ((len == name_len && strcmp(pathname, hymo_current_mirror_name) == 0) ||
            (len == path_len && strcmp(pathname, hymo_current_mirror_path) == 0)) {
            return true;
        }
    }

    if (!hymo_should_apply_hide_rules())
        return false;

    /* Bloom fast-path: path definitely not in hide list */
    if (atomic_read(&hymo_hide_count) != 0) {
        unsigned long bh1 = jhash(pathname, (u32)len, 0) & (HYMO_BLOOM_SIZE - 1);
        unsigned long bh2 = jhash(pathname, (u32)len, 1) & (HYMO_BLOOM_SIZE - 1);
        if (!test_bit(bh1, hymo_hide_bloom) || !test_bit(bh2, hymo_hide_bloom))
            return false;
    } else {
        return false;
    }

    /* Check hash table for explicit hide rules (fallback for non-inode paths) */
    hash = full_name_hash(NULL, pathname, len);
    rcu_read_lock();
    hlist_for_each_entry_rcu(hide_entry, &hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
        if (unlikely(hide_entry->path_hash == hash && strcmp(hide_entry->path, pathname) == 0)) {
            rcu_read_unlock();
            return true;
        }
    }
    rcu_read_unlock();

    return false;
}
EXPORT_SYMBOL(__hymofs_should_hide);
#endif /* CONFIG_HYMOFS_HIDE_ENTRIES */

bool __hymofs_should_spoof_mtime(const char *pathname)
{
    struct hymo_inject_entry *entry;
    u32 hash;
    bool found = false;
    pid_t current_pid;

    if (unlikely(!hymofs_enabled)) return false;
    if (unlikely(!pathname)) return false;

    /* Allow daemon process to see real mtime */
    current_pid = task_tgid_vnr(current);
    if (hymo_daemon_pid > 0 && current_pid == hymo_daemon_pid) {
        return false;
    }

    hash = full_name_hash(NULL, pathname, strlen(pathname));

    rcu_read_lock();
    hlist_for_each_entry_rcu(entry, &hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
        if (strcmp(entry->dir, pathname) == 0) {
            found = true;
            break;
        }
    }
    rcu_read_unlock();
    return found;
}
EXPORT_SYMBOL(__hymofs_should_spoof_mtime);

static bool __hymofs_should_replace(const char *pathname)
{
    struct hymo_entry *entry;
    u32 hash;
    size_t path_len;
    bool found = false;
    pid_t current_pid;

    if (unlikely(!hymofs_enabled)) return false;
    if (unlikely(!pathname)) return false;

    /* Allow daemon process to bypass replacement */
    current_pid = task_tgid_vnr(current);
    if (hymo_daemon_pid > 0 && current_pid == hymo_daemon_pid) {
        return false;
    }

    if (atomic_read(&hymo_rule_count) == 0)
        return false;

    path_len = strlen(pathname);
    /* Bloom fast-path: skip lookup when path is definitely not in rules (KPM backport) */
    {
        unsigned long bh1 = jhash(pathname, (u32)path_len, 0) & (HYMO_BLOOM_SIZE - 1);
        unsigned long bh2 = jhash(pathname, (u32)path_len, 1) & (HYMO_BLOOM_SIZE - 1);
        if (!test_bit(bh1, hymo_path_bloom) || !test_bit(bh2, hymo_path_bloom))
            return false;
    }

    hash = full_name_hash(NULL, pathname, path_len);
    rcu_read_lock();
    hlist_for_each_entry_rcu(entry, &hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
        if (unlikely(entry->src_hash == hash && strcmp(entry->src, pathname) == 0)) {
            found = true;
            break;
        }
    }
    rcu_read_unlock();
    return found;
}

struct hymo_merge_ctx {
    struct dir_context ctx;
    struct list_head *head;
    const char *dir_path;
};

static HYMO_FILLDIR_RET_TYPE hymo_merge_filldir(struct dir_context *ctx, const char *name, int namlen,
		      loff_t offset, u64 ino, unsigned int d_type)
{
    struct hymo_merge_ctx *mctx = container_of(ctx, struct hymo_merge_ctx, ctx);
    struct hymo_name_list *item;

    if (namlen == 1 && name[0] == '.') return HYMO_FILLDIR_CONTINUE;
    if (namlen == 2 && name[0] == '.' && name[1] == '.') return HYMO_FILLDIR_CONTINUE;

    /* Skip .replace marker */
    if (namlen == 8 && strncmp(name, ".replace", 8) == 0) return HYMO_FILLDIR_CONTINUE;

    /* Check for whiteout (char dev 0:0) */
    if (d_type == DT_CHR) {
        char *path = kasprintf(GFP_KERNEL, "%s/%.*s", mctx->dir_path, namlen, name);
        if (path) {
            struct kstat stat;
            struct path p;
            if (kern_path(path, LOOKUP_FOLLOW, &p) == 0) {
                if (vfs_getattr(&p, &stat, STATX_TYPE, AT_STATX_SYNC_AS_STAT) == 0) {
                    if (S_ISCHR(stat.mode) && stat.rdev == 0) {
                        /* It is a whiteout, skip injection */
                        path_put(&p);
                        kfree(path);
                        return HYMO_FILLDIR_CONTINUE;
                    }
                }
                path_put(&p);
            }
            kfree(path);
        }
    }

    /* Check for duplicates */
    {
        struct hymo_name_list *pos;
        list_for_each_entry(pos, mctx->head, list) {
            if (strlen(pos->name) == namlen && strncmp(pos->name, name, namlen) == 0) {
                return HYMO_FILLDIR_CONTINUE; /* Already exists */
            }
        }
    }

    item = kmalloc(sizeof(*item), GFP_KERNEL);
    if (item) {
        item->name = kstrndup(name, namlen, GFP_KERNEL);
        item->type = d_type;
        if (item->name) {
            list_add(&item->list, mctx->head);
        } else {
            kfree(item);
        }
    }
    return HYMO_FILLDIR_CONTINUE;
}

int hymofs_populate_injected_list(const char *dir_path, struct dentry *parent, struct list_head *head)
{
    struct hymo_entry *entry;
    struct hymo_inject_entry *inject_entry;
    struct hymo_merge_entry *merge_entry;
    struct hymo_name_list *item;
    u32 hash;
    int bkt;
    bool should_inject = false;
    struct list_head merge_targets;
    struct hymo_merge_target_node *target_node, *tmp_node;
    size_t dir_len;
    
    if (unlikely(!hymofs_enabled)) return 0;
    if (unlikely(!dir_path)) return 0;

    INIT_LIST_HEAD(&merge_targets);
    dir_len = strlen(dir_path);
    hash = full_name_hash(NULL, dir_path, dir_len);

    rcu_read_lock();
    
    hlist_for_each_entry_rcu(inject_entry, &hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
        if (strcmp(inject_entry->dir, dir_path) == 0) {
            should_inject = true;
            break;
        }
    }
    
    // Check for merge rule
    hlist_for_each_entry_rcu(merge_entry, &hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
        if (strcmp(merge_entry->src, dir_path) == 0) {
            target_node = kmalloc(sizeof(*target_node), GFP_ATOMIC);
            if (target_node) {
                target_node->target = kstrdup(merge_entry->target, GFP_ATOMIC);
                list_add_tail(&target_node->list, &merge_targets);
             should_inject = true;
        }
        }
    }

    if (should_inject) {
        // Static injections
        hash_for_each_rcu(hymo_paths, bkt, entry, node) {
            if (strncmp(entry->src, dir_path, dir_len) == 0) {
                char *name = NULL;
                if (dir_len == 1 && dir_path[0] == '/') {
                    name = entry->src + 1;
                } else if (entry->src[dir_len] == '/') {
                    name = entry->src + dir_len + 1;
                }

                if (name && *name && strchr(name, '/') == NULL) {
                    /* Check for duplicates */
                    bool exists = false;
                    struct hymo_name_list *pos;
                    list_for_each_entry(pos, head, list) {
                        if (strcmp(pos->name, name) == 0) {
                            exists = true;
                            break;
                        }
                    }

                    if (!exists) {
                    item = kmalloc(sizeof(*item), GFP_ATOMIC);
                    if (item) {
                        item->name = kstrdup(name, GFP_ATOMIC);
                        item->type = entry->type;
                        if (item->name) {
                            list_add(&item->list, head);
                        }
                        else kfree(item);
                        }
                    }
                }
            }
        }
    }

    rcu_read_unlock();

    // Dynamic merge (outside RCU lock, kern_path/iterate_dir may sleep)
    list_for_each_entry_safe(target_node, tmp_node, &merge_targets, list) {
        if (target_node->target) {
            struct path path;
            if (kern_path(target_node->target, LOOKUP_FOLLOW, &path) == 0) {
                /* Use init_cred (root) to ensure we can read the module directory 
                   regardless of the calling process's permissions */
                const struct cred *cred = get_task_cred(&init_task);
                struct file *f = dentry_open(&path, O_RDONLY | O_DIRECTORY, cred);
                if (!IS_ERR(f)) {
                    struct hymo_merge_ctx mctx = {
                        .ctx.actor = hymo_merge_filldir,
                        .head = head,
                        .dir_path = target_node->target
                    };
                    iterate_dir(f, &mctx.ctx);
                    fput(f);
                }
                put_cred(cred);
                path_put(&path);
            }
            kfree(target_node->target);
        }
        kfree(target_node);
    }

    return 0;
}
EXPORT_SYMBOL(hymofs_populate_injected_list);

struct filename *hymofs_handle_getname(struct filename *result)
{
    char *target = NULL;
    bool is_absolute;

    if (unlikely(IS_ERR(result))) return result;

    if (unlikely(!hymofs_enabled))
        return result;

    if (likely(hash_empty(hymo_paths) && 
               hash_empty(hymo_hide_paths) && 
               hash_empty(hymo_merge_dirs)))
        return result;

    is_absolute = (result->name[0] == '/');

    if (unlikely(hymofs_should_hide(result->name))) {
        putname(result);
        return ERR_PTR(-ENOENT);
    }

    if (likely(is_absolute)) {
        target = hymofs_resolve_target(result->name);
        if (unlikely(target)) {
            putname(result);
            result = getname_kernel(target);
            kfree(target);
        }
        return result;
    }

    /* Handle relative paths - optimized slow path */
    {
        char *buf = NULL;
        struct path pwd;
        char *cwd;
        int cwd_len, name_len;
        const char *name = result->name;

        /* Skip ./ prefix */
        if (name[0] == '.' && name[1] == '/') {
            name += 2;
        }

        /* Get current directory without spin_lock - use RCU */
        rcu_read_lock();
        pwd = current->fs->pwd;
        path_get(&pwd);
        rcu_read_unlock();

        /* Allocate buffer only after we have pwd */
        buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
        if (!buf) {
            path_put(&pwd);
            goto fallback_absolute;
        }

        /* Use d_path (hooked) to get the virtual path of CWD */
        cwd = d_path(&pwd, buf, PAGE_SIZE);
        path_put(&pwd);

        if (IS_ERR(cwd)) {
            kfree(buf);
            goto fallback_absolute;
        }

        cwd_len = strlen(cwd);
        name_len = strlen(name);

        /* Move to beginning of buffer to allow appending */
        if (cwd != buf) {
            memmove(buf, cwd, cwd_len + 1);
            cwd = buf;
        }

        if (cwd_len + 1 + name_len < PAGE_SIZE) {
            /* Construct absolute path: cwd + / + name */
            if (cwd_len > 0 && cwd[cwd_len - 1] != '/') {
                cwd[cwd_len++] = '/';
                cwd[cwd_len] = '\0';
            }
            memcpy(cwd + cwd_len, name, name_len + 1);

            /* Try to resolve the constructed absolute path */
            target = hymofs_resolve_target(cwd);
        }

        kfree(buf);
    }

fallback_absolute:
    /* If relative path resolution failed, try the original name */
    if (!target) {
        target = hymofs_resolve_target(result->name);
    }

    if (target) {
        putname(result);
        result = getname_kernel(target);
        kfree(target);
    }

    return result;
}
EXPORT_SYMBOL(hymofs_handle_getname);

/* Resolve relative path with dirfd for fstatat() merge support */
struct filename *hymofs_resolve_relative(int dfd, const char *name)
{
    struct fd f;
    struct filename *result = NULL;
    char *buf, *dir_path, *target;
    size_t dir_len, name_len;

    f = fdget(dfd);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0))
    if (fd_empty(f))
        return NULL;
#else
    if (!f.file)
        return NULL;
#endif

    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf)
        goto out_fdput;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0))
    dir_path = d_path(&fd_file(f)->f_path, buf, PATH_MAX);
#else
    dir_path = d_path(&f.file->f_path, buf, PATH_MAX);
#endif
    if (IS_ERR(dir_path))
        goto out_free;

    dir_len = strlen(dir_path);
    name_len = strlen(name);
    if (dir_len + 1 + name_len >= PATH_MAX)
        goto out_free;

    /* Build full path in-place */
    if (dir_path != buf)
        memmove(buf, dir_path, dir_len);
    if (dir_len > 0 && buf[dir_len - 1] != '/')
        buf[dir_len++] = '/';
    memcpy(buf + dir_len, name, name_len + 1);

    target = __hymofs_resolve_target(buf);
    if (target) {
        result = getname_kernel(target);
        if (IS_ERR(result))
            result = NULL;
        kfree(target);
    }

out_free:
    kfree(buf);
out_fdput:
    fdput(f);
    return result;
}
EXPORT_SYMBOL(hymofs_resolve_relative);

/* Bloom filter helper - add a filename */
static __always_inline void bloom_add(unsigned long *filter, const char *name, int namlen)
{
    u32 h1 = full_name_hash(NULL, name, namlen);
    __set_bit(h1 & HYMO_BLOOM_MASK, filter);  /* Non-atomic, faster */
    __set_bit((h1 >> 16) & HYMO_BLOOM_MASK, filter);
}

/* Bloom filter helper - test if filename might exist */
static __always_inline bool bloom_test(const unsigned long *filter, const char *name, int namlen)
{
    u32 h1 = full_name_hash(NULL, name, namlen);
    /* Use logical AND for boolean result */
    return test_bit(h1 & HYMO_BLOOM_MASK, filter) && 
           test_bit((h1 >> 16) & HYMO_BLOOM_MASK, filter);
}

/* Callback context for enumerating merge target directory */
struct bloom_fill_ctx {
    struct dir_context ctx;
    unsigned long *filter;
};

/* Callback to add each filename to bloom filter */
static HYMO_FILLDIR_RET_TYPE bloom_filldir(struct dir_context *ctx, const char *name, int namlen,
                          loff_t offset, u64 ino, unsigned int d_type)
{
    struct bloom_fill_ctx *bctx = container_of(ctx, struct bloom_fill_ctx, ctx);
    /* Skip . and .. */
    if (namlen == 1 && name[0] == '.')
        return HYMO_FILLDIR_CONTINUE;
    if (namlen == 2 && name[0] == '.' && name[1] == '.')
        return HYMO_FILLDIR_CONTINUE;
    bloom_add(bctx->filter, name, namlen);
    return HYMO_FILLDIR_CONTINUE;
}

void __hymofs_prepare_readdir(struct hymo_readdir_context *ctx, struct file *file)
{
    struct inode *dir_inode;
    int i;
    
    ctx->file = file;
    ctx->path_buf = NULL;
    ctx->dir_path = NULL;
    ctx->dir_path_len = 0;
    INIT_LIST_HEAD(&ctx->merge_targets);
    ctx->is_replace_mode = false;
    ctx->dir_has_hidden = false;
    ctx->has_merge_files = false;
    
    /* Initialize bloom filter */
    memset(ctx->bloom_filter, 0, sizeof(ctx->bloom_filter));
    
    /* Initialize merge files hash table */
    for (i = 0; i < HYMO_MERGE_HASH_SIZE; i++)
        INIT_HLIST_HEAD(&ctx->merge_files[i]);

    /* Fast path: Check if this directory has any hidden entries */
    if (file && file->f_path.dentry) {
        dir_inode = d_inode(file->f_path.dentry);
        if (dir_inode && dir_inode->i_mapping) {
            ctx->dir_has_hidden = test_bit(AS_FLAGS_HYMO_DIR_HAS_HIDDEN, 
                                           &dir_inode->i_mapping->flags);
        }
    }

    ctx->path_buf = (char *)__get_free_page(GFP_KERNEL);
    if (ctx->path_buf && file && file->f_path.dentry) {
        char *p = d_path(&file->f_path, ctx->path_buf, PAGE_SIZE);
        if (!IS_ERR(p)) {
            int len = strlen(p);
            memmove(ctx->path_buf, p, len + 1);
            ctx->dir_path = ctx->path_buf;
            ctx->dir_path_len = len;
            // hymo_log("readdir prepare: %s\n", ctx->dir_path);

            /* Check for merge rule */
            {
                struct hymo_merge_entry *entry;
                u32 hash = full_name_hash(NULL, ctx->dir_path, ctx->dir_path_len);
                
                rcu_read_lock();
                hlist_for_each_entry_rcu(entry, &hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
                    if (strcmp(entry->src, ctx->dir_path) == 0) {
                        struct hymo_merge_target_node *node = kmalloc(sizeof(*node), GFP_ATOMIC);
                        if (node) {
                            struct path target_path;
                            node->target = kstrdup(entry->target, GFP_ATOMIC);
                            node->target_dentry = NULL;
                            /* Cache the target dentry for fast lookup */
                            if (kern_path(entry->target, LOOKUP_FOLLOW, &target_path) == 0) {
                                node->target_dentry = dget(target_path.dentry);
                                path_put(&target_path);
                            }
                            list_add_tail(&node->list, &ctx->merge_targets);
                        }
                    }
                }
                rcu_read_unlock();

                /* Check for .replace marker in merge targets */
                if (!list_empty(&ctx->merge_targets)) {
                    struct hymo_merge_target_node *node;
                    list_for_each_entry(node, &ctx->merge_targets, list) {
                        char *replace_path = kasprintf(GFP_KERNEL, "%s/.replace", node->target);
                        if (replace_path) {
                            struct path path;
                            if (kern_path(replace_path, LOOKUP_FOLLOW, &path) == 0) {
                                ctx->is_replace_mode = true;
                                hymo_log("replace mode enabled for %s (found %s)\n", ctx->dir_path, replace_path);
                                path_put(&path);
                            }
                            kfree(replace_path);
                            if (ctx->is_replace_mode) break;
                        }
                    }
                    
                    /* Mark that we have merge files to check */
                    if (!ctx->is_replace_mode) {
                        ctx->has_merge_files = true;
                        
                        /* Build bloom filter by enumerating merge target directories */
                        list_for_each_entry(node, &ctx->merge_targets, list) {
                            if (node->target_dentry) {
                                struct file *target_file;
                                struct path target_path = {
                                    .mnt = file->f_path.mnt,
                                    .dentry = node->target_dentry
                                };
                                target_file = dentry_open(&target_path, O_RDONLY | O_DIRECTORY, current_cred());
                                if (!IS_ERR(target_file)) {
                                    struct bloom_fill_ctx bctx = {
                                        .ctx.actor = bloom_filldir,
                                        .filter = ctx->bloom_filter
                                    };
                                    iterate_dir(target_file, &bctx.ctx);
                                    fput(target_file);
                                }
                            }
                        }
                    }
                }
            }
        } else {
            free_page((unsigned long)ctx->path_buf);
            ctx->path_buf = NULL;
        }
    }
}
EXPORT_SYMBOL(__hymofs_prepare_readdir);

void __hymofs_cleanup_readdir(struct hymo_readdir_context *ctx)
{
    struct hymo_merge_target_node *node, *tmp;
    
    if (ctx->path_buf) free_page((unsigned long)ctx->path_buf);
    list_for_each_entry_safe(node, tmp, &ctx->merge_targets, list) {
        if (node->target_dentry)
            dput(node->target_dentry);
        kfree(node->target);
        kfree(node);
    }
}
EXPORT_SYMBOL(__hymofs_cleanup_readdir);

bool __hymofs_check_filldir(struct hymo_readdir_context *ctx, const char *name, int namlen)
{
    struct dentry *child;
    struct inode *inode;
    pid_t current_pid;
    struct hymo_merge_target_node *node;

    /* Root sees everything */
    if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
        return false;

    /* Allow daemon process to see all directory entries */
    current_pid = task_tgid_vnr(current);
    if (hymo_daemon_pid > 0 && current_pid == hymo_daemon_pid) {
        return false;
    }

    /* Fast path: If directory has no hidden entries and no merge files, skip all checks */
    if (likely(!ctx->dir_has_hidden && !ctx->has_merge_files))
        return false;  /* O(1) skip! */

    /* Skip . and .. - use single comparison where possible */
    if (unlikely(namlen <= 2 && name[0] == '.')) {
        if (namlen == 1 || (namlen == 2 && name[1] == '.'))
            return false;
    }

    /* Stealth mode: Hide hymo devices in /dev directory */
    if (hymo_stealth_enabled && ctx->dir_path) {
        /* Check if we're listing /dev directory */
        if (ctx->dir_path_len == 4 && strcmp(ctx->dir_path, "/dev") == 0) {
            size_t mirror_name_len = strlen(hymo_current_mirror_name);
            if (namlen == mirror_name_len && 
                memcmp(name, hymo_current_mirror_name, namlen) == 0) {
                return true;
            }
        }
    }

    /* If we are in replace mode, hide all original entries */
    if (unlikely(ctx->is_replace_mode))
        return true;

    /* Fast path: Use inode marking (O(1) bit test) */
    if (ctx->dir_has_hidden && !hymo_is_privileged_process() &&
        hymo_should_apply_hide_rules() && ctx->file && ctx->file->f_path.dentry) {
        child = d_hash_and_lookup(ctx->file->f_path.dentry, 
                                  &(struct qstr)QSTR_INIT(name, namlen));
        if (child) {
            inode = d_inode(child);
            if (inode && inode->i_mapping &&
                test_bit(AS_FLAGS_HYMO_HIDE, &inode->i_mapping->flags)) {
                dput(child);
                return true;
            }
            dput(child);
        }
    }

    /* Merge target check - files that exist in merge target should be hidden */
    if (ctx->has_merge_files) {
        /* Ultra fast path: Bloom filter says definitely not in merge target */
        if (!bloom_test(ctx->bloom_filter, name, namlen)) {
            return false;  /* O(1) skip - bloom filter negative */
        }
        
        /* Bloom filter positive - need to confirm with d_hash_and_lookup */
        list_for_each_entry(node, &ctx->merge_targets, list) {
            /* Fast path: use cached dentry + d_hash_and_lookup */
            if (node->target_dentry) {
                struct dentry *child = d_hash_and_lookup(node->target_dentry,
                                           &(struct qstr)QSTR_INIT(name, namlen));
                if (child) {
                    dput(child);
                    return true;
                }
            }
        }
    }

    return false;
}
EXPORT_SYMBOL(__hymofs_check_filldir);

struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[];
};

#ifdef CONFIG_HYMOFS_INJECT_ENTRIES
/* Inject virtual entries into getdents system call */
int hymofs_inject_entries(struct hymo_readdir_context *ctx, void __user **dir_ptr, int *count, loff_t *pos)
{
    struct linux_dirent __user *current_dir = *dir_ptr;
    struct list_head head;
    struct hymo_name_list *item, *tmp;
    loff_t current_idx = 0;
    loff_t start_idx;
    int injected = 0;
    int error = 0;
    int initial_count = *count;
    bool is_transition = (*pos < HYMO_MAGIC_POS);
    struct dentry *parent;

    if (!ctx->file) return 0;
    parent = ctx->file->f_path.dentry;

    if (is_transition) {
        start_idx = 0;
    } else {
        start_idx = *pos - HYMO_MAGIC_POS;
    }

    INIT_LIST_HEAD(&head);
    hymofs_populate_injected_list(ctx->dir_path, parent, &head);

    list_for_each_entry_safe(item, tmp, &head, list) {
        if (current_idx >= start_idx) {
            int name_len = strlen(item->name);
            int reclen = ALIGN(offsetof(struct linux_dirent, d_name) + name_len + 2, sizeof(long));
            if (*count >= reclen) {
                struct linux_dirent d;
                d.d_ino = 1;
                d.d_off = HYMO_MAGIC_POS + current_idx + 1;
                d.d_reclen = reclen;
                if (copy_to_user(current_dir, &d, offsetof(struct linux_dirent, d_name)) ||
                    copy_to_user(current_dir->d_name, item->name, name_len) ||
                    put_user(0, current_dir->d_name + name_len) ||
                    put_user(item->type, (char __user *)current_dir + reclen - 1)) {
                        error = -EFAULT;
                        break;
                }
                current_dir = (struct linux_dirent __user *)((char __user *)current_dir + reclen);
                *count -= reclen;
                injected++;
            } else {
                break;
            }
        }
        current_idx++;
        list_del(&item->list);
        kfree(item->name);
        kfree(item);
    }
    
    list_for_each_entry_safe(item, tmp, &head, list) {
        list_del(&item->list);
        kfree(item->name);
        kfree(item);
    }

    if (error == 0) {
        if (injected > 0) {
            if (is_transition) {
                *pos = HYMO_MAGIC_POS + injected;
            } else {
                *pos += injected;
            }
        }
        error = initial_count - *count;
    }
    
    *dir_ptr = current_dir;
    return error;
}
EXPORT_SYMBOL(hymofs_inject_entries);

/* Inject virtual entries into getdents64 system call */
int hymofs_inject_entries64(struct hymo_readdir_context *ctx, void __user **dir_ptr, int *count, loff_t *pos)
{
    struct linux_dirent64 __user *current_dir = *dir_ptr;
    struct list_head head;
    struct hymo_name_list *item, *tmp;
    loff_t current_idx = 0;
    loff_t start_idx;
    int injected = 0;
    int error = 0;
    int initial_count = *count;
    bool is_transition = (*pos < HYMO_MAGIC_POS);
    struct dentry *parent;

    if (!ctx->file) return 0;
    parent = ctx->file->f_path.dentry;

    if (is_transition) {
        start_idx = 0;
    } else {
        start_idx = *pos - HYMO_MAGIC_POS;
    }

    INIT_LIST_HEAD(&head);
    hymofs_populate_injected_list(ctx->dir_path, parent, &head);

    list_for_each_entry_safe(item, tmp, &head, list) {
        if (current_idx >= start_idx) {
            int name_len = strlen(item->name);
            int reclen = ALIGN(offsetof(struct linux_dirent64, d_name) + name_len + 1, sizeof(u64));
            if (*count >= reclen) {
                struct linux_dirent64 d;
                d.d_ino = 1;
                d.d_off = HYMO_MAGIC_POS + current_idx + 1;
                d.d_reclen = reclen;
                d.d_type = item->type;
                if (copy_to_user(current_dir, &d, offsetof(struct linux_dirent64, d_name)) ||
                    copy_to_user(current_dir->d_name, item->name, name_len) ||
                    put_user(0, current_dir->d_name + name_len)) {
                        error = -EFAULT;
                        break;
                }
                current_dir = (struct linux_dirent64 __user *)((char __user *)current_dir + reclen);
                *count -= reclen;
                injected++;
            } else {
                break;
            }
        }
        current_idx++;
        list_del(&item->list);
        kfree(item->name);
        kfree(item);
    }
    
    list_for_each_entry_safe(item, tmp, &head, list) {
        list_del(&item->list);
        kfree(item->name);
        kfree(item);
    }

    if (error == 0) {
        if (injected > 0) {
            if (is_transition) {
                *pos = HYMO_MAGIC_POS + injected;
            } else {
                *pos += injected;
            }
        }
        error = initial_count - *count;
    }
    
    *dir_ptr = current_dir;
    return error;
}
EXPORT_SYMBOL(hymofs_inject_entries64);
#endif /* CONFIG_HYMOFS_INJECT_ENTRIES */

#ifdef CONFIG_HYMOFS_STAT_SPOOF
static dev_t __attribute__((unused)) get_dev_for_path(const char *path_str) {
    struct path path;
    dev_t dev = 0;
    if (kern_path(path_str, LOOKUP_FOLLOW, &path) == 0) {
        if (path.dentry && path.dentry->d_sb) {
            dev = path.dentry->d_sb->s_dev;
        }
        path_put(&path);
    }
    return dev;
}

/* Update timestamps for injected directories to appear current */
extern char *d_absolute_path(const struct path *, char *, int);

/* Fast path check: determine if path might need HymoFS processing */
static inline bool hymofs_needs_check(const struct path *path)
{
    const struct dentry *dentry;
    const char *name;
    
    if (!path || !path->dentry)
        return false;
    
    dentry = path->dentry;
    name = dentry->d_name.name;
    
    /* Skip common system paths that never have HymoFS rules */
    if (name[0] == 'd' && !strncmp(name, "dev", 3))
        return false;
    if (name[0] == 'p' && !strncmp(name, "proc", 4))
        return false;
    if (name[0] == 's' && !strncmp(name, "sys", 3))
        return false;
    
    /* If no rules exist, skip all processing */
    if (atomic_read(&hymo_rule_count) == 0)
        return false;
    
    return true;
}

void hymofs_spoof_stat(const struct path *path, struct kstat *stat)
{
    char *buf, *virtual_buf = NULL;
    char *p;
    bool is_injected = false;
    gfp_t gfp = in_atomic() ? GFP_ATOMIC : GFP_KERNEL;

    /* Fast path checks - avoid all overhead if not needed */
    if (!hymofs_enabled) {
        atomic64_inc(&hymo_stats.fast_path_skips);
        return;
    }
    if (!hymo_stealth_enabled) {
        atomic64_inc(&hymo_stats.fast_path_skips);
        return;
    }
    
    /* Quick path validation */
    if (!hymofs_needs_check(path)) {
        atomic64_inc(&hymo_stats.fast_path_skips);
        return;
    }
    
    /* Check if rules tables are empty - ultimate fast path */
    if (likely(hash_empty(hymo_paths) && hash_empty(hymo_targets) && 
               hash_empty(hymo_inject_dirs))) {
        atomic64_inc(&hymo_stats.fast_path_skips);
        return;
    }
    
    atomic64_inc(&hymo_stats.total_checks);

    buf = kmalloc(PAGE_SIZE, gfp);
    if (!buf || !path || !path->dentry) {
        if (buf) kfree(buf);
        return;
    }

    /* Use d_absolute_path to bypass our own d_path hook and get the real physical path */
    p = d_absolute_path(path, buf, PAGE_SIZE);
    if (!IS_ERR(p)) {
        /* HymoFS: Check if this path is a merge target (physical path) and map back to virtual */
        virtual_buf = kmalloc(PAGE_SIZE, gfp);
        
        if (virtual_buf) {
            if (__hymofs_reverse_lookup(p, virtual_buf, PAGE_SIZE) > 0) {
                p = virtual_buf; /* Switch to virtual path */
                is_injected = true;
            }
        }

        /* Only spoof attributes for files we injected */
        if (is_injected) {
            /* Always look up parent to get correct fs attributes (dev, uid, gid) */
                char *last_slash = strrchr(p, '/');
                if (last_slash) {
                    struct path parent_path;
                    if (last_slash == p) {
                        /* Parent is root */
                        if (kern_path("/", LOOKUP_FOLLOW, &parent_path) == 0) {
                            struct inode *inode = d_backing_inode(parent_path.dentry);
                            stat->uid = inode->i_uid;
                            stat->gid = inode->i_gid;
                            stat->dev = inode->i_sb->s_dev;
                            path_put(&parent_path);
                        }
                    } else {
                        *last_slash = '\0';
                        if (kern_path(p, LOOKUP_FOLLOW, &parent_path) == 0) {
                            struct inode *inode = d_backing_inode(parent_path.dentry);
                            stat->uid = inode->i_uid;
                            stat->gid = inode->i_gid;
                            stat->dev = inode->i_sb->s_dev;
                            path_put(&parent_path);
                        } else {
                            /* Fallback if parent lookup fails (rare) */
                            if (strncmp(p, "/system/", 8) == 0 || 
                                strncmp(p, "/vendor/", 8) == 0 ||
                                strncmp(p, "/product/", 9) == 0 ||
                                strncmp(p, "/odm/", 5) == 0 ||
                                strncmp(p, "/apex/", 6) == 0) {
                                stat->uid = KUIDT_INIT(0);
                                stat->gid = KGIDT_INIT(0);
                            }
                        }
                        *last_slash = '/';
                    }
                }
                /* Obfuscate inode for injected files too */
                stat->ino ^= 0x48594D4F;
            }

        if (hymofs_should_spoof_mtime(p)) {
            ktime_get_real_ts64(&stat->mtime);
            stat->ctime = stat->mtime;
        }
        /* HymoFS: Inode obfuscation for redirected paths */
        if (__hymofs_should_replace(p)) {
            /* XOR with a magic number to make inode look different from target */
            stat->ino ^= 0x48594D4F;
            
            /* Fixup permissions for /system paths to ensure they look like root-owned */
            if (strncmp(p, "/system/", 8) == 0) {
                stat->uid = KUIDT_INIT(0);
                stat->gid = KGIDT_INIT(0);
            }
        }
        if (virtual_buf) kfree(virtual_buf);
    }
    kfree(buf);
}
EXPORT_SYMBOL(hymofs_spoof_stat);

/*
 * ==================== kstat Spoofing Implementation ====================
 * Allows full stat() result manipulation for specific inodes
 */

struct hymo_kstat_entry {
    unsigned long target_ino;
    struct {
        dev_t spoofed_dev;
        unsigned long spoofed_ino;
        unsigned int spoofed_nlink;
        loff_t spoofed_size;
        long spoofed_atime_sec;
        long spoofed_atime_nsec;
        long spoofed_mtime_sec;
        long spoofed_mtime_nsec;
        long spoofed_ctime_sec;
        long spoofed_ctime_nsec;
        unsigned long spoofed_blksize;
        unsigned long long spoofed_blocks;
    } info;
    struct hlist_node node;
    struct rcu_head rcu;
};

static DEFINE_HASHTABLE(hymo_kstat_entries, 8);

bool hymofs_is_kstat_spoofed(struct inode *inode)
{
    struct hymo_kstat_entry *entry;
    bool found = false;

    /* Early boot protection */
    if (system_state < SYSTEM_RUNNING) return false;
    if (!inode) return false;
    if (!hymofs_enabled) return false;

    rcu_read_lock();
    hash_for_each_possible_rcu(hymo_kstat_entries, entry, node, inode->i_ino) {
        if (entry->target_ino == inode->i_ino) {
            found = true;
            break;
        }
    }
    rcu_read_unlock();
    return found;
}
EXPORT_SYMBOL(hymofs_is_kstat_spoofed);

void hymofs_spoof_kstat_by_ino(unsigned long ino, struct kstat *stat)
{
    struct hymo_kstat_entry *entry;

    /* Early boot protection */
    if (system_state < SYSTEM_RUNNING) return;
    if (!stat) return;
    if (!hymofs_enabled) return;

    /* Root sees real values */
    if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
        return;

    rcu_read_lock();
    hash_for_each_possible_rcu(hymo_kstat_entries, entry, node, ino) {
        if (entry->target_ino == ino) {
            stat->dev = entry->info.spoofed_dev;
            stat->ino = entry->info.spoofed_ino;
            stat->nlink = entry->info.spoofed_nlink;
            stat->size = entry->info.spoofed_size;
            stat->atime.tv_sec = entry->info.spoofed_atime_sec;
            stat->atime.tv_nsec = entry->info.spoofed_atime_nsec;
            stat->mtime.tv_sec = entry->info.spoofed_mtime_sec;
            stat->mtime.tv_nsec = entry->info.spoofed_mtime_nsec;
            stat->ctime.tv_sec = entry->info.spoofed_ctime_sec;
            stat->ctime.tv_nsec = entry->info.spoofed_ctime_nsec;
            stat->blksize = entry->info.spoofed_blksize;
            stat->blocks = entry->info.spoofed_blocks;
            hymo_log("kstat: spoofed ino %lu\n", ino);
            break;
        }
    }
    rcu_read_unlock();
}
EXPORT_SYMBOL(hymofs_spoof_kstat_by_ino);

/* Get performance statistics */
void hymofs_get_perf_stats(struct hymofs_perf_info *info)
{
    if (!info)
        return;
    
    info->total_checks = atomic64_read(&hymo_stats.total_checks);
    info->fast_path_skips = atomic64_read(&hymo_stats.fast_path_skips);
    info->bloom_rejects = atomic64_read(&hymo_stats.bloom_rejects);
    info->rule_hits = atomic64_read(&hymo_stats.rule_hits);
}
EXPORT_SYMBOL(hymofs_get_perf_stats);
#endif /* CONFIG_HYMOFS_STAT_SPOOF */

#ifdef CONFIG_HYMOFS_STAT_SPOOF
/* Post-process getattr results for stat spoofing */
void hymofs_post_getattr(const struct path *path, struct inode *inode, 
                         struct kstat *stat, int ret)
{
    if (ret != 0)
        return;

    /* HymoFS: Spoof timestamps if needed */
    hymofs_spoof_stat(path, stat);
    
    /* Apply full kstat spoofing if configured for this inode */
    if (hymofs_is_kstat_spoofed(inode)) {
        hymofs_spoof_kstat_by_ino(inode->i_ino, stat);
    }
}
EXPORT_SYMBOL(hymofs_post_getattr);
#endif /* CONFIG_HYMOFS_STAT_SPOOF */

#ifdef CONFIG_HYMOFS_REVERSE_LOOKUP
/* Process d_path output for reverse lookup */
char *hymofs_process_d_path(char *res, char *buf, int buflen)
{
	char *temp = NULL;
	int len;

	if (unlikely(!hymofs_enabled))
		return res;

	if (likely(hash_empty(hymo_targets)))
		return res;

	if (IS_ERR(res))
		return res;

	/* Allocate temporary buffer for reverse lookup */
	temp = kmalloc(buflen, GFP_KERNEL);
	if (!temp)
		return res;

	/* Try reverse lookup */
	if (__hymofs_reverse_lookup(res, temp, buflen) == 0) {
		len = strlen(temp);
		/* Safety check: ensure we don't overflow the output buffer */
		if (len < buflen) {
			memcpy(buf, temp, len + 1); /* Copy including null terminator */
			res = buf;
		}
	}
	kfree(temp);
	return res;
}
EXPORT_SYMBOL(hymofs_process_d_path);
#endif /* CONFIG_HYMOFS_REVERSE_LOOKUP */

#ifdef CONFIG_HYMOFS_UNAME_SPOOF

/*
 * ==================== uname Spoofing Implementation ====================
 * Allows spoofing kernel version reported by uname()
 */

void hymofs_spoof_uname(struct new_utsname *name)
{
	pid_t current_pid;

	if (!name)
		return;

	/* Allow daemon process to see real uname */
	current_pid = task_tgid_vnr(current);
	if (hymo_daemon_pid > 0 && current_pid == hymo_daemon_pid) {
		return;
	}

	spin_lock(&hymo_uname_lock);
	if (hymo_uname_info.sysname[0])
		strscpy(name->sysname, hymo_uname_info.sysname, sizeof(name->sysname));
	if (hymo_uname_info.nodename[0])
		strscpy(name->nodename, hymo_uname_info.nodename, sizeof(name->nodename));
	if (hymo_uname_info.release[0])
		strscpy(name->release, hymo_uname_info.release, sizeof(name->release));
	if (hymo_uname_info.version[0])
		strscpy(name->version, hymo_uname_info.version, sizeof(name->version));
	if (hymo_uname_info.machine[0])
		strscpy(name->machine, hymo_uname_info.machine, sizeof(name->machine));
	if (hymo_uname_info.domainname[0])
		strscpy(name->domainname, hymo_uname_info.domainname, sizeof(name->domainname));
	spin_unlock(&hymo_uname_lock);
}
EXPORT_SYMBOL(hymofs_spoof_uname);
#endif /* CONFIG_HYMOFS_UNAME_SPOOF */

#ifdef CONFIG_HYMOFS_CMDLINE_SPOOF

/*
 * ==================== cmdline Spoofing Implementation ====================
 * Allows spoofing /proc/cmdline content
 */

static bool hymo_cmdline_spoofed = false;
static char *hymo_fake_cmdline = NULL;

bool hymofs_is_cmdline_spoofed(void)
{
    return hymo_cmdline_spoofed && hymo_fake_cmdline != NULL;
}

int hymofs_spoof_cmdline(struct seq_file *m)
{
    if (!hymo_cmdline_spoofed || !hymo_fake_cmdline)
        return 1;  /* Return 1 to indicate "not spoofed, use original" */

    /* Root sees real cmdline */
    if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
        return 1;

    seq_puts(m, hymo_fake_cmdline);
    seq_putc(m, '\n');
    hymo_log("cmdline: spoofed\n");
    return 0;  /* Return 0 to indicate "spoofed successfully" */
}
EXPORT_SYMBOL(hymofs_spoof_cmdline);
#endif /* CONFIG_HYMOFS_CMDLINE_SPOOF */

#ifdef CONFIG_HYMOFS_XATTR_FILTER


bool hymofs_is_overlay_xattr(struct dentry *dentry, const char *name)
{
    struct hymo_xattr_sb_entry *sb_entry;
    bool found = false;

    if (!name) return false;
    if (strncmp(name, "trusted.overlay.", 16) != 0) return false;
    
    if (!dentry) return false;

    rcu_read_lock();
    hlist_for_each_entry_rcu(sb_entry, &hymo_xattr_sbs[hash_min((unsigned long)dentry->d_sb, HYMO_HASH_BITS)], node) {
        if (sb_entry->sb == dentry->d_sb) {
            found = true;
            break;
        }
    }
    rcu_read_unlock();
    
    return found;
}
EXPORT_SYMBOL(hymofs_is_overlay_xattr);

ssize_t hymofs_filter_xattrs(struct dentry *dentry, char *klist, ssize_t len)
{
    struct hymo_xattr_sb_entry *sb_entry;
    bool should_filter = false;
    char *p = klist;
    char *end = klist + len;
    char *out = klist;
    ssize_t new_len = 0;
    
    if (!dentry) return len;

    rcu_read_lock();
    hlist_for_each_entry_rcu(sb_entry, &hymo_xattr_sbs[hash_min((unsigned long)dentry->d_sb, HYMO_HASH_BITS)], node) {
        if (sb_entry->sb == dentry->d_sb) {
            should_filter = true;
            break;
        }
    }
    rcu_read_unlock();

    if (!should_filter) return len;

    while (p < end) {
        size_t slen = strlen(p);
        if (strncmp(p, "trusted.overlay.", 16) != 0) {
            if (out != p)
                memmove(out, p, slen + 1);
            out += slen + 1;
            new_len += slen + 1;
        }
        p += slen + 1;
    }
#endif /* CONFIG_HYMOFS_XATTR_FILTER */
    return new_len;
}
EXPORT_SYMBOL(hymofs_filter_xattrs);

#endif /* CONFIG_HYMOFS */
