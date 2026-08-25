/*
 * Kasumi - per-open virtual file backend.
 *
 * A virtual fd owns a real target file for ordinary I/O.  Regular-file mmap
 * is deliberately served from a private shmem snapshot so the VMA never
 * inherits the target filesystem's address-space or vm_ops contract.  The
 * source identity is retained separately for the optional maps projection.
 */
#ifndef _KASUMI_VIRTUAL_FILE_H
#define _KASUMI_VIRTUAL_FILE_H

#include <linux/fs.h>
#include <linux/stddef.h>
#include <linux/types.h>

struct task_struct;
struct kasumi_virtual_exec_alias;

struct kasumi_virtual_exec_binding {
	struct kasumi_virtual_exec_alias *previous;
	struct kasumi_virtual_exec_alias *installed;
};

/*
 * @handled is false when this backend intentionally declines the request and
 * the caller should preserve the legacy path redirect.  Once true, the
 * return value is the final open result and must not be retried through VFS.
 */
int kasumi_virtual_open_entry_fd(const char *visible_path, int flags,
				 umode_t mode, bool *handled);
int kasumi_virtual_open_entry_fd_flags(const char *visible_path, int flags,
				       umode_t mode,
				       unsigned int lookup_flags,
				       bool *handled);
int kasumi_virtual_open_exec_fd(const char *visible_path, int flags,
				bool *handled);
int kasumi_virtual_reopen_fd(const char *visible_path, unsigned int source_fd,
			     int flags, bool *handled);
bool kasumi_virtual_entry_matches(const char *visible_path);
bool kasumi_virtual_file_getattr_fd(unsigned int fd, struct kstat *stat);
bool kasumi_virtual_file_get_source_fd(unsigned int fd, struct path *source);
bool kasumi_virtual_file_get_visible_fd(unsigned int fd, char *visible_path,
					 size_t visible_path_size);
bool kasumi_virtual_file_get_target_fd(unsigned int fd,
				       unsigned long *target_ino,
				       unsigned long *target_dev);
int kasumi_virtual_exec_bind_current(const char *visible_path,
				     unsigned long target_ino,
				     unsigned long target_dev);
int kasumi_virtual_exec_begin_current(
	const char *visible_path, unsigned long target_ino,
	unsigned long target_dev, struct kasumi_virtual_exec_binding *binding);
void kasumi_virtual_exec_finish_current(
	struct kasumi_virtual_exec_binding *binding, bool committed);
void kasumi_virtual_exec_clear_current(void);
bool kasumi_virtual_exec_get_current(char *visible_path,
				     size_t visible_path_size);
void kasumi_virtual_exec_task_fork(struct task_struct *parent,
				   struct task_struct *child);
void kasumi_virtual_exec_task_exit(struct task_struct *task);
bool kasumi_virtual_file_lookup_path(const struct path *path,
				     char *visible_path,
				     size_t visible_path_size);
bool kasumi_virtual_file_lookup_maps(unsigned long target_ino,
					     unsigned long target_dev,
					     unsigned long *spoofed_ino,
					     unsigned long *spoofed_dev,
					     char *spoofed_pathname,
					     size_t spoofed_pathname_size);

void kasumi_virtual_file_stop_new(void);
void kasumi_virtual_file_shutdown(void);
unsigned int kasumi_virtual_file_live(void);
u64 kasumi_virtual_file_open_count(void);
u64 kasumi_virtual_dir_iterate_count(void);

#endif /* _KASUMI_VIRTUAL_FILE_H */
