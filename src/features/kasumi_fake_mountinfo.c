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

static u64 g_cache_gen;  /* bumped every regenerate */

static struct fake_mi_cursor g_cursors[FAKE_MI_CURSORS];
static DEFINE_SPINLOCK(g_cursors_lock);

static atomic_t fake_mi_reader_pid = ATOMIC_INIT(0);

/* Symbols resolved via kallsyms at init. */
static struct file *(*ptr_filp_open)(const char *, int, umode_t);
static int (*ptr_filp_close)(struct file *, fl_owner_t);
static ssize_t (*ptr_kernel_read)(struct file *, void *, size_t, loff_t *);

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
                       bool *is_ksu)
{
    size_t i = 0, token_start, token_end;
    size_t j;

    *is_ksu = false;
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

    /* Skip major:minor, root, mountpoint, mount opts. */
    for (j = 0; j < 4; j++) {
        if (!skip_token(line, len, &i))
            return false;
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

struct id_map_entry {
    int old_id;
    int new_id;
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

static void map_add_if_missing(struct id_map_entry *map, int *nmap,
                               int max_entries, int old_id, int *next_id)
{
    if (!map || !nmap || !next_id || old_id <= 0 || *nmap >= max_entries)
        return;
    if (map_lookup(map, *nmap, old_id) >= 0)
        return;

    map[*nmap].old_id = old_id;
    map[*nmap].new_id = (*next_id)++;
    (*nmap)++;
}

/* Build the new mountinfo buffer from the current hidden task's real
 * /proc/self/mountinfo view. If userspace namespace hiding has already removed
 * module mounts, use that view as the base; then drop any remaining KSU-source
 * lines as a conservative kernel-side fallback and compact mount ids.
 */
static int build_fake_buffer(const char *raw, size_t raw_len,
                             char *out, size_t out_cap, size_t *out_len)
{
    struct id_map_entry *mount_map;
    struct id_map_entry *prop_map;
    int n_mount_map = 0;
    int n_prop_map = 0;
    int next_mount_id = 1;
    int next_prop_id = 1;
    size_t in = 0, o = 0;

    mount_map = kvmalloc_array(MAX_MOUNTS, sizeof(*mount_map), GFP_KERNEL);
    if (!mount_map)
        return -ENOMEM;

    prop_map = kvmalloc_array(MAX_MOUNTS, sizeof(*prop_map), GFP_KERNEL);
    if (!prop_map) {
        kvfree(mount_map);
        return -ENOMEM;
    }

    /* Pass 1: assign new ids to non-KSU lines in original order. */
    in = 0;
    while (in < raw_len) {
        size_t ls = in;
        int mi, pi;
        size_t ms, me, ps, pe;
        struct fake_mi_prop_ref prop_refs[FAKE_MI_MAX_PROP_FIELDS];
        size_t prop_count = 0;
        bool ksu;
        size_t j;

        while (in < raw_len && raw[in] != '\n') in++;
        if (parse_line(raw + ls, in - ls, &mi, &pi,
                       &ms, &me, &ps, &pe,
                       prop_refs, &prop_count, &ksu)) {
            if (!ksu) {
                map_add_if_missing(mount_map, &n_mount_map, MAX_MOUNTS,
                                   mi, &next_mount_id);
                for (j = 0; j < prop_count; j++) {
                    map_add_if_missing(prop_map, &n_prop_map, MAX_MOUNTS,
                                       prop_refs[j].old_id, &next_prop_id);
                }
            }
        }
        if (in < raw_len) in++;
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
        size_t line_len;
        int new_mi = -1, new_pi = -1;
        size_t cursor;
        int n;
        size_t j;

        while (in < raw_len && raw[in] != '\n') in++;
        line_len = in - ls;

        if (!parse_line(raw + ls, line_len, &mi, &pi,
                        &ms, &me, &ps, &pe,
                        prop_refs, &prop_count, &ksu) || ksu) {
            if (in < raw_len) in++;
            continue;
        }

        new_mi = map_lookup(mount_map, n_mount_map, mi);
        new_pi = map_lookup(mount_map, n_mount_map, pi);
        if (new_mi < 0) new_mi = mi;
        /* If parent was filtered (shouldn't happen: KSU mounts are leaves in
         * practice), leave parent_id as its original value — detectors would
         * see an orphan id rather than a contradiction.
         */
        if (new_pi < 0) new_pi = pi;

        /* Reserve for "\n" + safety margin. */
        if (o + line_len + 32 > out_cap)
            break;

        n = scnprintf(out + o, out_cap - o, "%d", new_mi);
        o += n;
        memcpy(out + o, raw + ls + me, ps - me);
        o += ps - me;
        n = scnprintf(out + o, out_cap - o, "%d", new_pi);
        o += n;
        cursor = pe;

        for (j = 0; j < prop_count; j++) {
            int new_prop = map_lookup(prop_map, n_prop_map, prop_refs[j].old_id);

            if (new_prop < 0)
                new_prop = prop_refs[j].old_id;
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

    kvfree(prop_map);
    kvfree(mount_map);
    *out_len = o;
    return 0;
}

/* Caller must hold g_cache.lock. */
static int regenerate_cache_locked(void)
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

    if (!ptr_filp_open || !ptr_kernel_read || !ptr_filp_close)
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

    ret = build_fake_buffer(scratch, total, new_buf, FAKE_MI_BUF_MAX, &new_len);
    if (ret != 0)
        goto out_free;

    g_cache.slots[new_slot].len = new_len;
    smp_wmb();
    WRITE_ONCE(g_cache.active_slot, new_slot);
    WRITE_ONCE(g_cache.last_jiffies, jiffies);
    WRITE_ONCE(g_cache.valid, true);
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
    g_cache.valid = false;
    g_cache.last_jiffies = 0;
    mutex_unlock(&g_cache.lock);
}

int kasumi_fake_mi_prepare(bool force)
{
    int ret = 0;

    mutex_lock(&g_cache.lock);
    if (force || !g_cache.valid ||
        time_after(jiffies, g_cache.last_jiffies +
                             msecs_to_jiffies(FAKE_MI_TTL_MS)))
        ret = regenerate_cache_locked();
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
        return 0;

    (void)kasumi_fake_mi_prepare(false);

    mutex_lock(&g_cache.lock);
    cache_buf = fake_mi_active_buf_locked(&cache_len);
    if (!g_cache.valid || !cache_buf) {
        mutex_unlock(&g_cache.lock);
        return 0;
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
        return -1;  /* caller interprets: override ret to 0 */
    }

    avail = cache_len - pos;
    to_copy = count < avail ? count : avail;

    if (copy_to_user(userbuf, cache_buf + pos, to_copy)) {
        mutex_unlock(&g_cache.lock);
        return 0;
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

    if (!iocb || !to)
        return -EINVAL;
    file = iocb->ki_filp;
    if (!file)
        return -EINVAL;

    (void)kasumi_fake_mi_prepare(false);

    mutex_lock(&g_cache.lock);
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
    (void)kasumi_fake_mi_prepare(false);

    mutex_lock(&g_cache.lock);
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
    char *cache_buf;
    size_t cache_len;

    if (!path || !path[0])
        return -EINVAL;

    path_len = strlen(path);

    rcu_read_lock();
    if (!READ_ONCE(g_cache.valid)) {
        ret = -EAGAIN;
        goto out_unlock;
    }

    slot = READ_ONCE(g_cache.active_slot);
    if (slot < 0 || slot >= FAKE_MI_BUF_SLOTS) {
        ret = -EAGAIN;
        goto out_unlock;
    }

    smp_rmb();
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

    ptr_filp_open  = (void *)kasumi_lookup_name("filp_open");
    ptr_filp_close = (void *)kasumi_lookup_name("filp_close");
    ptr_kernel_read = (void *)kasumi_lookup_name("kernel_read");

    if (!ptr_filp_open || !ptr_filp_close || !ptr_kernel_read) {
        pr_warn("Kasumi fake_mi: symbol resolution failed (filp_open=%p filp_close=%p kernel_read=%p); feature disabled\n",
                ptr_filp_open, ptr_filp_close, ptr_kernel_read);
        return -ENOSYS;
    }

    for (i = 0; i < FAKE_MI_BUF_SLOTS; i++) {
        g_cache.slots[i].buf = vmalloc(FAKE_MI_BUF_MAX);
        if (!g_cache.slots[i].buf)
            goto out_free_slots;
        g_cache.slots[i].len = 0;
    }
    g_cache.active_slot = 0;
    g_cache.valid = false;

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

    mutex_lock(&g_cache.lock);
    g_cache.valid = false;
    mutex_unlock(&g_cache.lock);

    synchronize_rcu();

    mutex_lock(&g_cache.lock);
    for (i = 0; i < FAKE_MI_BUF_SLOTS; i++) {
        vfree(g_cache.slots[i].buf);
        g_cache.slots[i].buf = NULL;
        g_cache.slots[i].len = 0;
    }
    g_cache.valid = false;
    mutex_unlock(&g_cache.lock);
}
