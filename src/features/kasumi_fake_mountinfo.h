/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - interfaces for fake mountinfo cache generation and serving.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _KASUMI_FAKE_MOUNTINFO_H
#define _KASUMI_FAKE_MOUNTINFO_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/uio.h>

struct path;
struct mnt_namespace;

int kasumi_fake_mi_init(void);
void kasumi_fake_mi_exit(void);
bool kasumi_fake_mi_active(void);

/* Refresh the current mount namespace's fake mountinfo snapshot when it is
 * missing, stale, or belongs to another namespace.
 * Safe to call from process context before userland starts reading
 * /proc/.../mountinfo; the per-open producer proxy should stay copy-only.
 */
int kasumi_fake_mi_prepare(bool force);

/* True while this CPU is currently performing a kernel-internal mountinfo
 * read for cache regeneration. The proxy must bypass filtering in this
 * state to avoid infinite recursion.
 */
bool kasumi_fake_mi_is_internal_read(void);

/*
 * Serve fake mountinfo to a marked app that just completed a real sys_read
 * or sys_pread64 on /proc/<pid>/mountinfo.
 *
 * @file:     the struct file * corresponding to the fd (for cursor keying)
 * @userbuf:  user-space destination (same pointer the app passed to read)
 * @count:    number of bytes the app asked for
 * @kernel_ret: the kernel's own read result (bytes written to userbuf)
 * @explicit_pos: byte offset requested by pread64, or -1 for normal read()
 *
 * Returns:
 *   > 0: new ret value to report to user
 *   0: feature disabled, caller may fall back
 *   < 0: cache/copy error; an active fake view must fail closed
 *
 * On success the function has already overwritten userbuf with fake content
 * and, for read(), advanced the per-file cursor.
 */
ssize_t kasumi_fake_mi_serve(struct file *file, void __user *userbuf,
                           size_t count, ssize_t kernel_ret,
                           loff_t explicit_pos);

/* Direct read_iter helper for per-file read proxies. Returns:
 *   > 0 bytes copied
 *   = 0 EOF
 *   < 0 cache unavailable / copy failure, caller should fall back
 */
ssize_t kasumi_fake_mi_read_iter(struct kiocb *iocb, struct iov_iter *to);

/* Look up the fake mount ID assigned to an exact mountpoint path in the
 * current cached fake mountinfo snapshot. Returns >0 on success, <0 when the
 * cache/path is unavailable or no exact mountpoint entry exists.
 */
int kasumi_fake_mi_lookup_mount_id(const char *path);

/* Atomic-context variant for syscall tracepoint/kprobe paths. It only reads
 * an already prepared cache and never regenerates or takes a sleeping lock.
 */
int kasumi_fake_mi_lookup_mount_id_cached(const char *path);

/* Resolve translation, visibility, and the hidden mount root's projected
 * mount-root state from one namespace+root-keyed RCU-stable cache generation.
 */
int kasumi_fake_mi_mount_id_state_cached(u64 real_id, int *fake_id,
					 bool *hidden,
					 bool *projected_mount_root);

/* Drop per-file cursor state when the file is closed or refreshed. Called
 * lazily from serve() based on LRU; no explicit close hook needed.
 */
void kasumi_fake_mi_invalidate_all(void);
u64 kasumi_fake_mi_generation(void);
void kasumi_fake_mi_poll_wait(struct file *file,
			      struct poll_table_struct *wait);
void kasumi_fake_mi_poll_wake(void);

/* Whole-file transforms for an open-bound proc mount snapshot.  The visible
 * variant also records one visibility bit per raw mount-list ordinal so the
 * sibling mounts rendering can be filtered without collapsing stacked mounts
 * that share a mountpoint. */
int kasumi_fake_mi_build_from_raw(const char *raw, size_t raw_len,
				  char *out, size_t out_cap, size_t *out_len);
int kasumi_fake_mi_build_from_raw_visible(const char *raw, size_t raw_len,
					  char *out, size_t out_cap,
					  size_t *out_len,
					  unsigned long *visible_bitmap,
					  size_t visible_bits,
					  size_t *raw_line_count);
/* If @ns/@root are the current task's exact open-bound view, publish the
 * supplied transform as the statx/statfs cache after verifying it byte-for-byte
 * against an id-map-producing rebuild. Other target views are ignored. When a
 * cache commit occurs, @published_generation receives that exact generation;
 * it remains zero for an ignored target view.
 */
int kasumi_fake_mi_publish_current_snapshot(
	const char *raw, size_t raw_len, const char *fake, size_t fake_len,
	struct mnt_namespace *ns, const struct path *root,
	u64 *published_generation);
#endif /* _KASUMI_FAKE_MOUNTINFO_H */
