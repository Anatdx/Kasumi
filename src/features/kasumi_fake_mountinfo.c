/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - fake mountinfo cache generation and serving for hidden-app views.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include "kasumi_fake_mountinfo.h"
#include "kasumi_entrypoints.h"

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/rcupdate.h>
#include <linux/nsproxy.h>
#include <linux/version.h>

/* Cache sizing: mountinfo is typically 20-80KB on Android; cap at 512KB. */
#define FAKE_MI_BUF_MAX    (512 * 1024)
#define FAKE_MI_SCRATCH    (512 * 1024)
#define FAKE_MI_TTL_MS     500
#define FAKE_MI_BUF_SLOTS  2

/* Per-file cursor table for stateful chunked reads. Size chosen to cover
 * concurrent marked-app open()s; simple linear scan with LRU eviction.
 */
#define FAKE_MI_CURSORS    128
#define FAKE_MI_CURSOR_TTL_SEC  30

struct fake_mi_cache {
    struct {
        char *buf;
        size_t len;
        struct nsproxy *nsproxy;
        struct mnt_namespace *mnt_ns;
    } slots[FAKE_MI_BUF_SLOTS];
    int active_slot;
    unsigned long last_jiffies;
    bool valid;
    struct mutex lock;
};

struct fake_mi_cursor {
    struct file *file;   /* key: fd's file pointer (not dereferenced) */
    pid_t tgid;          /* key tiebreaker in case of pointer reuse */
    size_t pos;          /* byte offset into cache->buf */
    unsigned long ts;    /* last-used jiffies */
    u64 cache_gen;       /* generation this cursor was bound to */
};

static struct fake_mi_cache g_cache = {
    .active_slot = 0,
    .valid = false,
};

static bool fake_mi_initialized;

static u64 g_cache_gen;  /* bumped every regenerate */
static int fake_mi_last_error;

static struct fake_mi_cursor g_cursors[FAKE_MI_CURSORS];
static DEFINE_SPINLOCK(g_cursors_lock);

static atomic_t fake_mi_reader_pid = ATOMIC_INIT(0);

/* Symbols resolved via kallsyms at init. */
static struct file *(*ptr_filp_open)(const char *, int, umode_t);
static int (*ptr_filp_close)(struct file *, fl_owner_t);
static ssize_t (*ptr_kernel_read)(struct file *, void *, size_t, loff_t *);
static void (*ptr_free_nsproxy)(struct nsproxy *);

static struct mnt_namespace *fake_mi_current_mnt_ns(void)
{
    struct nsproxy *nsproxy = current->nsproxy;

    return nsproxy ? nsproxy->mnt_ns : NULL;
}

/* put_nsproxy() calls the non-exported free_nsproxy() on the final reference.
 * Keep the inline refcount operation here and call its kallsyms-resolved body
 * without adding an exported-symbol dependency.
 */
static KASUMI_NOCFI void fake_mi_put_nsproxy(struct nsproxy *nsproxy)
{
    bool release;

    if (!nsproxy)
        return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
    release = refcount_dec_and_test(&nsproxy->count);
#else
    release = atomic_dec_and_test(&nsproxy->count);
#endif
    if (release)
        ptr_free_nsproxy(nsproxy);
}

static void fake_mi_release_slot_owner_locked(int slot)
{
    struct nsproxy *nsproxy;

    if (slot < 0 || slot >= FAKE_MI_BUF_SLOTS)
        return;

    nsproxy = g_cache.slots[slot].nsproxy;
    g_cache.slots[slot].nsproxy = NULL;
    g_cache.slots[slot].mnt_ns = NULL;
    fake_mi_put_nsproxy(nsproxy);
}

static char *fake_mi_active_buf_locked(size_t *len)
{
    int slot = READ_ONCE(g_cache.active_slot);

    if (slot < 0 || slot >= FAKE_MI_BUF_SLOTS)
        return NULL;
    if (len)
        *len = g_cache.slots[slot].len;
    return g_cache.slots[slot].buf;
}

bool kasumi_fake_mi_is_internal_read(void)
{
    return atomic_read(&fake_mi_reader_pid) == task_pid_nr(current);
}

/* ------------------------------------------------------------------ */
/* Line parser                                                         */
/* ------------------------------------------------------------------ */

static inline bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

#define FAKE_MI_MAX_PROP_FIELDS 8

struct fake_mi_prop_ref {
    size_t value_start;
    size_t value_end;
    int old_id;
};

static bool parse_decimal_token(const char *line, size_t start, size_t end, int *out)
{
    long v;
    char tmp[32];
    size_t len;

    if (!out || start >= end)
        return false;

    len = end - start;
    if (len >= sizeof(tmp))
        return false;

    memcpy(tmp, line + start, len);
    tmp[len] = 0;
    if (kstrtol(tmp, 10, &v))
        return false;

    *out = (int)v;
    return true;
}

static bool skip_token(const char *line, size_t len, size_t *pos)
{
    size_t i = *pos;

    if (i >= len)
        return false;
    while (i < len && line[i] != ' ')
        i++;
    if (i >= len || line[i] != ' ')
        return false;
    *pos = i + 1;
    return true;
}

static bool token_has_prefix(const char *line, size_t start, size_t end,
                             const char *prefix)
{
    size_t plen = strlen(prefix);

    return end >= start + plen &&
           memcmp(line + start, prefix, plen) == 0;
}

/*
 * Parse one mountinfo line and extract:
 *   - mnt_id / parent_id
 *   - source == KSU
 *   - propagation-group numeric suffixes inside optional fields
 *
 * The returned byte ranges let us rewrite only the numeric pieces while
 * keeping the rest of the kernel-generated line byte-for-byte intact.
 *
 * mountinfo format:
 *   <mnt_id> <parent_id> <major:minor> <root> <mp> <opts> <optional_fields> - <fstype> <source> <sb_opts>
 */
static bool parse_line(const char *line, size_t len,
                       int *mnt_id, int *parent_id,
                       size_t *mi_start, size_t *mi_end,
                       size_t *pi_start, size_t *pi_end,
                       struct fake_mi_prop_ref *prop_refs, size_t *prop_count,
                       bool *is_ksu, bool *is_namespace_root)
{
    size_t i = 0, token_start, token_end;
    size_t j;

    *is_ksu = false;
    *is_namespace_root = false;
    if (prop_count)
        *prop_count = 0;

    /* mnt_id */
    *mi_start = i;
    while (i < len && is_digit(line[i]))
        i++;
    if (i == *mi_start || i >= len || line[i] != ' ')
        return false;
    *mi_end = i;
    if (!parse_decimal_token(line, *mi_start, *mi_end, mnt_id))
        return false;
    i++;

    /* parent_id */
    *pi_start = i;
    while (i < len && is_digit(line[i]))
        i++;
    if (i == *pi_start || i >= len || line[i] != ' ')
        return false;
    *pi_end = i;
    if (!parse_decimal_token(line, *pi_start, *pi_end, parent_id))
        return false;
    i++;

    /* Skip major:minor, root, mountpoint, mount opts. A self-parent entry is
     * only a legitimate graph terminator when it is mounted at namespace /.
     */
    for (j = 0; j < 4; j++) {
        token_start = i;
        if (!skip_token(line, len, &i))
            return false;
        if (j == 2 && i == token_start + 2 && line[token_start] == '/')
            *is_namespace_root = true;
    }

    while (i < len) {
        int value;

        token_start = i;
        while (i < len && line[i] != ' ')
            i++;
        token_end = i;
        if (token_start == token_end)
            return false;

        if (token_end == token_start + 1 && line[token_start] == '-') {
            if (i < len && line[i] == ' ')
                i++;
            break;
        }

        if (prop_refs && prop_count && *prop_count < FAKE_MI_MAX_PROP_FIELDS) {
            size_t value_start = 0;
            const char *prefix = NULL;

            if (token_has_prefix(line, token_start, token_end, "shared:")) {
                prefix = "shared:";
            } else if (token_has_prefix(line, token_start, token_end, "master:")) {
                prefix = "master:";
            } else if (token_has_prefix(line, token_start, token_end,
                                        "propagate_from:")) {
                prefix = "propagate_from:";
            }

            if (prefix) {
                value_start = token_start + strlen(prefix);
                if (value_start < token_end &&
                    parse_decimal_token(line, value_start, token_end, &value)) {
                    prop_refs[*prop_count].value_start = value_start;
                    prop_refs[*prop_count].value_end = token_end;
                    prop_refs[*prop_count].old_id = value;
                    (*prop_count)++;
                }
            }
        }

        if (i < len && line[i] == ' ')
            i++;
    }

    /* fstype */
    if (!skip_token(line, len, &i))
        return false;

    /* source */
    token_start = i;
    while (i < len && line[i] != ' ')
        i++;
    token_end = i;
    if (token_start == token_end)
        return false;
    if (token_end - token_start == 3 &&
        line[token_start] == 'K' &&
        line[token_start + 1] == 'S' &&
        line[token_start + 2] == 'U')
        *is_ksu = true;

    return true;
}

static bool parse_line_target(const char *line, size_t len,
                              int *mnt_id,
                              size_t *target_start, size_t *target_end)
{
    size_t i = 0;
    size_t token_start;
    size_t token_end;
    size_t j;

    if (!mnt_id || !target_start || !target_end)
        return false;

    token_start = i;
    while (i < len && is_digit(line[i]))
        i++;
    if (i == token_start || i >= len || line[i] != ' ')
        return false;
    token_end = i;
    if (!parse_decimal_token(line, token_start, token_end, mnt_id))
        return false;
    i++;

    for (j = 0; j < 3; j++) {
        if (!skip_token(line, len, &i))
            return false;
    }

    *target_start = i;
    while (i < len && line[i] != ' ')
        i++;
    if (i == *target_start)
        return false;
    *target_end = i;
    return true;
}

/* ------------------------------------------------------------------ */
/* Cache regeneration                                                  */
/* ------------------------------------------------------------------ */

#define MAX_MOUNTS 4096
#define MAX_PROP_IDS (MAX_MOUNTS * FAKE_MI_MAX_PROP_FIELDS)

struct id_map_entry {
    int old_id;
    int new_id;
};

struct mount_map_entry {
    int old_id;
    int parent_id;
    int new_id;
    int resolved_parent_id;
    unsigned int walk_cookie;
    bool graph_validated;
    bool namespace_root;
};

static int map_lookup(const struct id_map_entry *map, int nmap, int old_id)
{
    int i;

    for (i = 0; i < nmap; i++) {
        if (map[i].old_id == old_id)
            return map[i].new_id;
    }
    return -1;
}

static int map_add_if_missing(struct id_map_entry *map, int *nmap,
                              int max_entries, int old_id, int *next_id)
{
    if (!map || !nmap || !next_id || old_id <= 0)
        return -EINVAL;
    if (map_lookup(map, *nmap, old_id) >= 0)
        return 0;
    if (*nmap >= max_entries)
        return -E2BIG;

    map[*nmap].old_id = old_id;
    map[*nmap].new_id = (*next_id)++;
    (*nmap)++;
    return 0;
}

static int mount_map_lookup(const struct mount_map_entry *map, int nmap,
                            int old_id)
{
    int i;

    for (i = 0; i < nmap; i++) {
        if (map[i].old_id == old_id)
            return i;
    }
    return -1;
}

static int mount_map_add(struct mount_map_entry *map, int *nmap,
                         int old_id, int parent_id, bool visible,
                         bool namespace_root, int *next_id)
{
    if (!map || !nmap || !next_id || old_id <= 0 || parent_id <= 0)
        return -EINVAL;
    if (mount_map_lookup(map, *nmap, old_id) >= 0)
        return -EEXIST;
    if (*nmap >= MAX_MOUNTS)
        return -E2BIG;

    map[*nmap].old_id = old_id;
    map[*nmap].parent_id = parent_id;
    map[*nmap].new_id = visible ? (*next_id)++ : -1;
    map[*nmap].resolved_parent_id = 0;
    map[*nmap].walk_cookie = 0;
    map[*nmap].graph_validated = false;
    map[*nmap].namespace_root = namespace_root;
    (*nmap)++;
    return 0;
}

static int mount_map_validate_graph(struct mount_map_entry *map, int nmap)
{
    unsigned int cookie = 0;
    int i;

    for (i = 0; i < nmap; i++) {
        int node_idx = i;
        int hops;
        int j;

        if (map[i].graph_validated)
            continue;
        cookie++;
        for (hops = 0; hops <= nmap; hops++) {
            int parent;

            if (map[node_idx].graph_validated)
                break;
            if (map[node_idx].walk_cookie == cookie)
                return -ELOOP;
            map[node_idx].walk_cookie = cookie;
            if (map[node_idx].old_id == map[node_idx].parent_id) {
                if (!map[node_idx].namespace_root)
                    return -ELOOP;
                break;
            }
            parent = mount_map_lookup(map, nmap,
                                      map[node_idx].parent_id);
            if (parent < 0)
                break;
            node_idx = parent;
        }
        if (hops > nmap)
            return -ELOOP;
        for (j = 0; j < nmap; j++) {
            if (map[j].walk_cookie == cookie)
                map[j].graph_validated = true;
        }
    }

    for (i = 0; i < nmap; i++)
        map[i].walk_cookie = 0;
    return 0;
}

static int mount_map_resolve_parent(struct mount_map_entry *map, int nmap,
                                    const struct id_map_entry *external_map,
                                    int n_external, int old_parent_id,
                                    unsigned int walk_cookie, int *resolved)
{
    int current_id = old_parent_id;
    int result = -1;
    int hops;

    if (!resolved)
        return -EINVAL;

    for (hops = 0; hops <= nmap; hops++) {
        int idx = mount_map_lookup(map, nmap, current_id);

        /* A parent outside the visible mountinfo root has no line of its own. */
        if (idx < 0) {
            result = map_lookup(external_map, n_external, current_id);
            if (result < 0)
                return -ENOENT;
            break;
        }
        if (map[idx].new_id > 0) {
            result = map[idx].new_id;
            break;
        }
        if (map[idx].resolved_parent_id > 0) {
            result = map[idx].resolved_parent_id;
            break;
        }

        /* A mount tree cannot contain a parent cycle. Reject malformed input. */
        if (map[idx].walk_cookie == walk_cookie)
            return -ELOOP;

        map[idx].walk_cookie = walk_cookie;
        current_id = map[idx].parent_id;
    }

    if (result < 0)
        return -ELOOP;

    /* Cache the resolved visible/external ancestor on every hidden node in
     * this walk. Shared hidden chains are then resolved once rather than once
     * per visible child.
     */
    current_id = old_parent_id;
    for (hops = 0; hops <= nmap; hops++) {
        int idx = mount_map_lookup(map, nmap, current_id);

        if (idx < 0 || map[idx].new_id > 0 ||
            map[idx].resolved_parent_id > 0 ||
            map[idx].walk_cookie != walk_cookie)
            break;
        map[idx].resolved_parent_id = result;
        current_id = map[idx].parent_id;
    }

    *resolved = result;
    return 0;
}

static size_t decimal_len(int value)
{
    char buf[16];

    return scnprintf(buf, sizeof(buf), "%d", value);
}

/* Build the new mountinfo buffer from the current hidden task's real
 * /proc/self/mountinfo view. If userspace namespace hiding has already removed
 * module mounts, use that view as the base; then drop any remaining KSU-source
 * lines as a conservative kernel-side fallback and compact mount ids.
 */
static int build_fake_buffer(const char *raw, size_t raw_len,
                             char *out, size_t out_cap, size_t *out_len)
{
    struct mount_map_entry *mount_map;
    struct id_map_entry *prop_map;
    struct id_map_entry *external_map;
    int n_mount_map = 0;
    int n_prop_map = 0;
    int n_external = 0;
    int next_mount_id = 1;
    int next_prop_id = 1;
    unsigned int parent_walk_cookie = 1;
    int i;
    int ret = 0;
    size_t in = 0, o = 0;

    mount_map = kvmalloc_array(MAX_MOUNTS, sizeof(*mount_map), GFP_KERNEL);
    if (!mount_map)
        return -ENOMEM;

    prop_map = kvmalloc_array(MAX_PROP_IDS, sizeof(*prop_map), GFP_KERNEL);
    if (!prop_map) {
        kvfree(mount_map);
        return -ENOMEM;
    }
    external_map = kvmalloc_array(MAX_MOUNTS, sizeof(*external_map),
                                  GFP_KERNEL);
    if (!external_map) {
        kvfree(prop_map);
        kvfree(mount_map);
        return -ENOMEM;
    }

    /* Pass 1: retain the complete parent graph and assign compact ids only
     * to non-KSU lines in original order.
     */
    in = 0;
    while (in < raw_len) {
        size_t ls = in;
        int mi, pi;
        size_t ms, me, ps, pe;
        struct fake_mi_prop_ref prop_refs[FAKE_MI_MAX_PROP_FIELDS];
        size_t prop_count = 0;
        bool ksu;
        bool namespace_root;
        size_t j;

        while (in < raw_len && raw[in] != '\n') in++;
        if (!parse_line(raw + ls, in - ls, &mi, &pi,
                        &ms, &me, &ps, &pe,
                        prop_refs, &prop_count, &ksu, &namespace_root)) {
            ret = -EINVAL;
            goto out;
        }
        ret = mount_map_add(mount_map, &n_mount_map, mi, pi, !ksu,
                            namespace_root, &next_mount_id);
        if (ret)
            goto out;
        if (!ksu) {
            for (j = 0; j < prop_count; j++) {
                ret = map_add_if_missing(prop_map, &n_prop_map,
                                         MAX_PROP_IDS,
                                         prop_refs[j].old_id,
                                         &next_prop_id);
                if (ret)
                    goto out;
            }
        }
        if (in < raw_len) in++;
    }

    ret = mount_map_validate_graph(mount_map, n_mount_map);
    if (ret)
        goto out;

    /* Compact external parents after all visible IDs so a namespace-root
     * parent cannot collide with any emitted mount ID.
     */
    for (i = 0; i < n_mount_map; i++) {
        if (mount_map_lookup(mount_map, n_mount_map,
                             mount_map[i].parent_id) >= 0)
            continue;
        ret = map_add_if_missing(external_map, &n_external, MAX_MOUNTS,
                                 mount_map[i].parent_id,
                                 &next_mount_id);
        if (ret)
            goto out;
    }

    /* Pass 2: rewrite. */
    in = 0;
    while (in < raw_len) {
        size_t ls = in;
        int mi, pi;
        size_t ms, me, ps, pe;
        struct fake_mi_prop_ref prop_refs[FAKE_MI_MAX_PROP_FIELDS];
        size_t prop_count = 0;
        bool ksu;
        bool namespace_root;
        size_t line_len;
        int new_mi, new_pi;
        size_t cursor;
        int n;
        size_t j;

        while (in < raw_len && raw[in] != '\n') in++;
        line_len = in - ls;

        if (!parse_line(raw + ls, line_len, &mi, &pi,
                        &ms, &me, &ps, &pe,
                        prop_refs, &prop_count, &ksu, &namespace_root)) {
            ret = -EINVAL;
            goto out;
        }
        if (ksu) {
            if (in < raw_len) in++;
            continue;
        }

        n = mount_map_lookup(mount_map, n_mount_map, mi);
        if (n < 0 || mount_map[n].new_id <= 0) {
            ret = -ENOENT;
            goto out;
        }
        new_mi = mount_map[n].new_id;
        parent_walk_cookie++;
        ret = mount_map_resolve_parent(mount_map, n_mount_map,
                                       external_map, n_external, pi,
                                       parent_walk_cookie, &new_pi);
        if (ret)
            goto out;

        {
            size_t rewritten_len = line_len - (me - ms) - (pe - ps) +
                                   decimal_len(new_mi) + decimal_len(new_pi);

            for (j = 0; j < prop_count; j++) {
                int new_prop = map_lookup(prop_map, n_prop_map,
                                          prop_refs[j].old_id);

                if (new_prop < 0) {
                    ret = -ENOENT;
                    goto out;
                }
                rewritten_len -= prop_refs[j].value_end -
                                 prop_refs[j].value_start;
                rewritten_len += decimal_len(new_prop);
            }
            if (in < raw_len)
                rewritten_len++;
            if (rewritten_len > out_cap - o) {
                ret = -E2BIG;
                goto out;
            }
        }

        n = scnprintf(out + o, out_cap - o, "%d", new_mi);
        o += n;
        memcpy(out + o, raw + ls + me, ps - me);
        o += ps - me;
        n = scnprintf(out + o, out_cap - o, "%d", new_pi);
        o += n;
        cursor = pe;

        for (j = 0; j < prop_count; j++) {
            int new_prop = map_lookup(prop_map, n_prop_map, prop_refs[j].old_id);

            if (new_prop < 0) {
                ret = -ENOENT;
                goto out;
            }
            memcpy(out + o, raw + ls + cursor,
                   prop_refs[j].value_start - cursor);
            o += prop_refs[j].value_start - cursor;
            n = scnprintf(out + o, out_cap - o, "%d", new_prop);
            o += n;
            cursor = prop_refs[j].value_end;
        }

        memcpy(out + o, raw + ls + cursor, line_len - cursor);
        o += line_len - cursor;

        if (in < raw_len) {
            out[o++] = '\n';
            in++;
        }
    }

    *out_len = o;
out:
    kvfree(external_map);
    kvfree(prop_map);
    kvfree(mount_map);
    return ret;
}

/* Caller must hold g_cache.lock.
 *
 * KASUMI_NOCFI is REQUIRED: this function makes indirect calls through
 * kallsyms-resolved pointers (ptr_filp_open / ptr_kernel_read). On strict
 * jump-table-CFI kernels, filp_open and kernel_read have NO .cfi_jt thunk
 * (they are never address-taken in the kernel), so kasumi_lookup_callable()
 * can only return their RAW body address. Calling a raw address indirectly
 * from CFI-instrumented code is a CFI violation -> fatal trap. Disabling CFI
 * on this function's outbound indirect calls is the only fix (BTI is still
 * satisfied: the raw bodies start with paciasp/bti-c landing pads).
 */
static KASUMI_NOCFI int regenerate_cache_locked(struct nsproxy *owner_nsproxy)
{
    struct file *f;
    char *scratch = NULL;
    char *new_buf;
    size_t total = 0;
    size_t new_len = 0;
    loff_t pos = 0;
    ssize_t r;
    int new_slot;
    int ret = -EIO;

    if (!ptr_filp_open || !ptr_kernel_read || !ptr_filp_close ||
        !owner_nsproxy || !owner_nsproxy->mnt_ns)
        return -ENOSYS;

    new_slot = READ_ONCE(g_cache.active_slot) ^ 1;
    if (new_slot < 0 || new_slot >= FAKE_MI_BUF_SLOTS ||
        !g_cache.slots[new_slot].buf)
        return -ENOMEM;
    new_buf = g_cache.slots[new_slot].buf;

    /* The inactive slot may have been the previous active cache. Wait for
     * atomic readers to leave before reusing its storage.
     */
    synchronize_rcu();
    fake_mi_release_slot_owner_locked(new_slot);

    atomic_set(&fake_mi_reader_pid, task_pid_nr(current));
    f = ptr_filp_open("/proc/self/mountinfo", O_RDONLY, 0);
    if (IS_ERR(f)) {
        ret = PTR_ERR(f);
        kasumi_log("fake_mi: filp_open(/proc/self/mountinfo) failed pid=%d comm=%s ret=%d\n",
                 task_pid_nr(current), current->comm, ret);
        atomic_set(&fake_mi_reader_pid, 0);
        return ret;
    }

    scratch = vmalloc(FAKE_MI_SCRATCH);
    if (!scratch) {
        ret = -ENOMEM;
        goto out_close;
    }

    while (total < FAKE_MI_SCRATCH) {
        r = ptr_kernel_read(f, scratch + total, FAKE_MI_SCRATCH - total, &pos);
        if (r < 0) {
            ret = r;
            kasumi_log("fake_mi: kernel_read(/proc/self/mountinfo) failed pid=%d comm=%s ret=%zd pos=%lld total=%zu\n",
                     task_pid_nr(current), current->comm, r,
                     (long long)pos, total);
            goto out_free;
        }
        if (r == 0)
            break;
        total += r;
    }

    if (total == FAKE_MI_SCRATCH) {
        char extra;

        r = ptr_kernel_read(f, &extra, 1, &pos);
        if (r < 0) {
            ret = r;
            goto out_free;
        }
        if (r > 0) {
            ret = -E2BIG;
            kasumi_log("fake_mi: mountinfo exceeds scratch capacity pid=%d comm=%s\n",
                     task_pid_nr(current), current->comm);
            goto out_free;
        }
    }

    ret = build_fake_buffer(scratch, total, new_buf, FAKE_MI_BUF_MAX, &new_len);
    if (ret != 0) {
        kasumi_log("fake_mi: rebuild failed pid=%d comm=%s ret=%d raw_len=%zu\n",
                 task_pid_nr(current), current->comm, ret, total);
        goto out_free;
    }

    g_cache.slots[new_slot].len = new_len;
    g_cache.slots[new_slot].nsproxy = owner_nsproxy;
    g_cache.slots[new_slot].mnt_ns = owner_nsproxy->mnt_ns;
    smp_store_release(&g_cache.active_slot, new_slot);
    WRITE_ONCE(g_cache.last_jiffies, jiffies);
    smp_store_release(&g_cache.valid, true);
    g_cache_gen++;
    ret = 0;
    kasumi_log("fake_mi: regenerated pid=%d comm=%s raw_len=%zu fake_len=%zu gen=%llu\n",
             task_pid_nr(current), current->comm, total, new_len,
             (unsigned long long)g_cache_gen);

out_free:
    if (scratch) vfree(scratch);
out_close:
    ptr_filp_close(f, NULL);
    atomic_set(&fake_mi_reader_pid, 0);
    return ret;
}

/* Caller must hold g_cache.lock. This makes namespace selection, cache
 * generation and the caller's subsequent cache access one transaction.
 */
static int fake_mi_prepare_locked(bool force)
{
    struct mnt_namespace *mnt_ns = fake_mi_current_mnt_ns();
    struct nsproxy *owner_nsproxy;
    int slot;
    int ret;

    if (!mnt_ns)
        ret = -ESRCH;
    else {
        slot = READ_ONCE(g_cache.active_slot);
        if (!force && g_cache.valid &&
            slot >= 0 && slot < FAKE_MI_BUF_SLOTS &&
            g_cache.slots[slot].mnt_ns == mnt_ns &&
            !time_after(jiffies, g_cache.last_jiffies +
                                  msecs_to_jiffies(FAKE_MI_TTL_MS)))
            return 0;

        owner_nsproxy = current->nsproxy;
        if (!owner_nsproxy || owner_nsproxy->mnt_ns != mnt_ns)
            ret = -ESRCH;
        else {
            get_nsproxy(owner_nsproxy);
            ret = regenerate_cache_locked(owner_nsproxy);
            if (!ret)
                owner_nsproxy = NULL;
            fake_mi_put_nsproxy(owner_nsproxy);
        }
    }

    if (ret) {
        /* Never let an older namespace snapshot survive a failed rebuild. */
        smp_store_release(&g_cache.valid, false);
        fake_mi_last_error = ret;
    } else {
        fake_mi_last_error = 0;
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* Per-file cursor management                                          */
/* ------------------------------------------------------------------ */

/* Find existing cursor for (file, tgid) or allocate a slot (LRU-evict).
 * Caller must hold g_cursors_lock. Returns index into g_cursors.
 */
static int cursor_locate_locked(struct file *f, pid_t tgid, u64 cur_gen)
{
    int i;
    int free_slot = -1;
    int oldest = -1;
    unsigned long oldest_ts = ULONG_MAX;
    unsigned long now = jiffies;
    unsigned long ttl = FAKE_MI_CURSOR_TTL_SEC * HZ;

    for (i = 0; i < FAKE_MI_CURSORS; i++) {
        struct fake_mi_cursor *c = &g_cursors[i];
        if (c->file == f && c->tgid == tgid) {
            if (c->cache_gen != cur_gen) {
                c->pos = 0;
                c->cache_gen = cur_gen;
            }
            c->ts = now;
            return i;
        }
    }
    /* Not found: find free or LRU slot. */
    for (i = 0; i < FAKE_MI_CURSORS; i++) {
        struct fake_mi_cursor *c = &g_cursors[i];
        if (c->file == NULL) {
            free_slot = i;
            break;
        }
        if (time_after(now, c->ts + ttl)) {
            free_slot = i;
            break;
        }
        if (c->ts < oldest_ts) {
            oldest_ts = c->ts;
            oldest = i;
        }
    }
    if (free_slot < 0)
        free_slot = oldest >= 0 ? oldest : 0;

    {
        struct fake_mi_cursor *c = &g_cursors[free_slot];
        c->file = f;
        c->tgid = tgid;
        c->pos = 0;
        c->ts = now;
        c->cache_gen = cur_gen;
    }
    return free_slot;
}

void kasumi_fake_mi_invalidate_all(void)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&g_cursors_lock, flags);
    for (i = 0; i < FAKE_MI_CURSORS; i++)
        g_cursors[i].file = NULL;
    spin_unlock_irqrestore(&g_cursors_lock, flags);

    mutex_lock(&g_cache.lock);
    smp_store_release(&g_cache.valid, false);
    fake_mi_last_error = 0;
    g_cache.last_jiffies = 0;
    synchronize_rcu();
    for (i = 0; i < FAKE_MI_BUF_SLOTS; i++)
        fake_mi_release_slot_owner_locked(i);
    mutex_unlock(&g_cache.lock);
}

int kasumi_fake_mi_prepare(bool force)
{
    int ret = 0;

    /*
     * Reentrancy guard: regenerate_cache_locked() does filp_open/kernel_read
     * on /proc/self/mountinfo, which re-enters the openat redirect -> here.
     * Without this, the inner call would mutex_lock(&g_cache.lock) already held
     * by this task -> self-deadlock. Skip the inner prepare (cache is being
     * regenerated by us right now).
     */
    if (kasumi_fake_mi_is_internal_read())
        return 0;

    mutex_lock(&g_cache.lock);
    ret = fake_mi_prepare_locked(force);
    mutex_unlock(&g_cache.lock);

    return ret;
}

/* ------------------------------------------------------------------ */
/* Public serve                                                        */
/* ------------------------------------------------------------------ */

ssize_t kasumi_fake_mi_serve(struct file *file, void __user *userbuf,
                           size_t count, ssize_t kernel_ret,
                           loff_t explicit_pos)
{
    ssize_t ret;
    size_t avail;
    size_t to_copy;
    int idx;
    size_t pos;
    unsigned long flags;
    u64 gen;
    bool use_explicit_pos = explicit_pos >= 0;
    char *cache_buf;
    size_t cache_len;

    if (!file || !userbuf)
        return -EINVAL;

    mutex_lock(&g_cache.lock);
    ret = fake_mi_prepare_locked(false);
    if (ret) {
        mutex_unlock(&g_cache.lock);
        return ret;
    }
    cache_buf = fake_mi_active_buf_locked(&cache_len);
    if (!g_cache.valid || !cache_buf) {
        mutex_unlock(&g_cache.lock);
        return READ_ONCE(fake_mi_initialized) ? -EAGAIN : 0;
    }
    gen = g_cache_gen;

    if (use_explicit_pos) {
        pos = (size_t)explicit_pos;
    } else {
        /* Resolve cursor position. */
        spin_lock_irqsave(&g_cursors_lock, flags);
        idx = cursor_locate_locked(file, current->tgid, gen);
        pos = g_cursors[idx].pos;
        spin_unlock_irqrestore(&g_cursors_lock, flags);
    }

    if (pos >= cache_len) {
        /* EOF: report 0 bytes, user loop exits. */
        mutex_unlock(&g_cache.lock);
        /* Also clear cursor so a subsequent lseek-to-0 would start fresh;
         * simpler: leave it, a reused fd gets cursor=0 when cache_gen bumps.
         */
        return -ENODATA;  /* caller interprets: override ret to 0 */
    }

    avail = cache_len - pos;
    to_copy = count < avail ? count : avail;

    if (copy_to_user(userbuf, cache_buf + pos, to_copy)) {
        mutex_unlock(&g_cache.lock);
        return -EFAULT;
    }
    mutex_unlock(&g_cache.lock);

    /* Unused kernel_ret: we fully replace kernel output. */
    (void)kernel_ret;

    if (!use_explicit_pos) {
        spin_lock_irqsave(&g_cursors_lock, flags);
        /* Cursor might have been evicted between unlock/lock; re-locate. */
        idx = cursor_locate_locked(file, current->tgid, gen);
        g_cursors[idx].pos = pos + to_copy;
        spin_unlock_irqrestore(&g_cursors_lock, flags);
    }

    ret = (ssize_t)to_copy;
    return ret;
}

ssize_t kasumi_fake_mi_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
    struct file *file;
    size_t avail;
    size_t to_copy;
    size_t copied;
    loff_t pos;
    char *cache_buf;
    size_t cache_len;
    int ret;

    if (!iocb || !to)
        return -EINVAL;
    file = iocb->ki_filp;
    if (!file)
        return -EINVAL;

    mutex_lock(&g_cache.lock);
    ret = fake_mi_prepare_locked(false);
    if (ret) {
        mutex_unlock(&g_cache.lock);
        return ret;
    }
    cache_buf = fake_mi_active_buf_locked(&cache_len);
    if (!g_cache.valid || !cache_buf) {
        mutex_unlock(&g_cache.lock);
        return -EAGAIN;
    }

    pos = iocb->ki_pos;
    if (pos < 0 || (size_t)pos >= cache_len) {
        mutex_unlock(&g_cache.lock);
        return 0;
    }

    avail = cache_len - (size_t)pos;
    to_copy = min_t(size_t, iov_iter_count(to), avail);
    copied = copy_to_iter(cache_buf + pos, to_copy, to);
    mutex_unlock(&g_cache.lock);

    if (copied == 0)
        return -EFAULT;

    iocb->ki_pos = pos + copied;
    return (ssize_t)copied;
}

int kasumi_fake_mi_lookup_mount_id(const char *path)
{
    size_t path_len;
    size_t in = 0;
    int ret = -ENOENT;
    char *cache_buf;
    size_t cache_len;

    if (!path || !path[0])
        return -EINVAL;

    path_len = strlen(path);
    mutex_lock(&g_cache.lock);
    ret = fake_mi_prepare_locked(false);
    if (ret)
        goto out_unlock;
    cache_buf = fake_mi_active_buf_locked(&cache_len);
    if (!g_cache.valid || !cache_buf) {
        ret = -EAGAIN;
        goto out_unlock;
    }

    while (in < cache_len) {
        size_t ls = in;
        int mi;
        size_t target_start;
        size_t target_end;
        size_t line_len;

        while (in < cache_len && cache_buf[in] != '\n')
            in++;
        line_len = in - ls;
        if (parse_line_target(cache_buf + ls, line_len, &mi,
                              &target_start, &target_end) &&
            target_end - target_start == path_len &&
            memcmp(cache_buf + ls + target_start, path, path_len) == 0) {
            ret = mi;
            goto out_unlock;
        }
        if (in < cache_len)
            in++;
    }

out_unlock:
    mutex_unlock(&g_cache.lock);
    return ret;
}

int kasumi_fake_mi_lookup_mount_id_cached(const char *path)
{
    size_t path_len;
    size_t in = 0;
    int ret = -ENOENT;
    int slot;
    struct mnt_namespace *mnt_ns;
    char *cache_buf;
    size_t cache_len;

    if (!path || !path[0])
        return -EINVAL;

    path_len = strlen(path);

    rcu_read_lock();
    if (!smp_load_acquire(&g_cache.valid)) {
        ret = -EAGAIN;
        goto out_unlock;
    }

    slot = smp_load_acquire(&g_cache.active_slot);
    if (slot < 0 || slot >= FAKE_MI_BUF_SLOTS) {
        ret = -EAGAIN;
        goto out_unlock;
    }

    mnt_ns = fake_mi_current_mnt_ns();
    if (!mnt_ns || READ_ONCE(g_cache.slots[slot].mnt_ns) != mnt_ns) {
        ret = -EAGAIN;
        goto out_unlock;
    }

    cache_buf = READ_ONCE(g_cache.slots[slot].buf);
    cache_len = READ_ONCE(g_cache.slots[slot].len);
    if (!cache_buf || cache_len == 0) {
        ret = -EAGAIN;
        goto out_unlock;
    }

    while (in < cache_len) {
        size_t ls = in;
        int mi;
        size_t target_start;
        size_t target_end;
        size_t line_len;

        while (in < cache_len && cache_buf[in] != '\n')
            in++;
        line_len = in - ls;
        if (parse_line_target(cache_buf + ls, line_len, &mi,
                              &target_start, &target_end) &&
            target_end - target_start == path_len &&
            memcmp(cache_buf + ls + target_start, path, path_len) == 0) {
            ret = mi;
            goto out_unlock;
        }
        if (in < cache_len)
            in++;
    }

out_unlock:
    rcu_read_unlock();
    return ret;
}

/* ------------------------------------------------------------------ */
/* Init / exit                                                         */
/* ------------------------------------------------------------------ */

int kasumi_fake_mi_init(void)
{
    int i;

    mutex_init(&g_cache.lock);
    memset(g_cursors, 0, sizeof(g_cursors));

    ptr_filp_open  = (void *)kasumi_lookup_callable("filp_open");
    ptr_filp_close = (void *)kasumi_lookup_callable("filp_close");
    ptr_kernel_read = (void *)kasumi_lookup_callable("kernel_read");
    ptr_free_nsproxy = (void *)kasumi_lookup_callable("free_nsproxy");

    if (!ptr_filp_open || !ptr_filp_close || !ptr_kernel_read ||
        !ptr_free_nsproxy) {
        pr_warn("Kasumi fake_mi: symbol resolution failed (filp_open=%p filp_close=%p kernel_read=%p free_nsproxy=%p); feature disabled\n",
                ptr_filp_open, ptr_filp_close, ptr_kernel_read,
                ptr_free_nsproxy);
        return -ENOSYS;
    }

    for (i = 0; i < FAKE_MI_BUF_SLOTS; i++) {
        g_cache.slots[i].buf = vmalloc(FAKE_MI_BUF_MAX);
        if (!g_cache.slots[i].buf)
            goto out_free_slots;
        g_cache.slots[i].len = 0;
        g_cache.slots[i].nsproxy = NULL;
        g_cache.slots[i].mnt_ns = NULL;
    }
    g_cache.active_slot = 0;
    smp_store_release(&g_cache.valid, false);
    fake_mi_last_error = 0;

    WRITE_ONCE(fake_mi_initialized, true);

    pr_info("Kasumi fake_mi: initialized (current-view mountinfo)\n");
    return 0;

out_free_slots:
    while (--i >= 0) {
        vfree(g_cache.slots[i].buf);
        g_cache.slots[i].buf = NULL;
        g_cache.slots[i].len = 0;
    }
    return -ENOMEM;
}

void kasumi_fake_mi_exit(void)
{
    int i;

    if (!READ_ONCE(fake_mi_initialized))
        return;

    WRITE_ONCE(fake_mi_initialized, false);
    mutex_lock(&g_cache.lock);
    smp_store_release(&g_cache.valid, false);
    fake_mi_last_error = 0;
    synchronize_rcu();
    for (i = 0; i < FAKE_MI_BUF_SLOTS; i++) {
        fake_mi_release_slot_owner_locked(i);
        vfree(g_cache.slots[i].buf);
        g_cache.slots[i].buf = NULL;
        g_cache.slots[i].len = 0;
    }
    g_cache.valid = false;
    mutex_unlock(&g_cache.lock);
}

bool kasumi_fake_mi_active(void)
{
    return READ_ONCE(fake_mi_initialized);
}
