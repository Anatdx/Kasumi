/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - per-file virtual view identity tracking.
 */
#ifndef _KASUMI_FILE_VIEW_H
#define _KASUMI_FILE_VIEW_H

#include <linux/types.h>
#include <linux/stddef.h>

int kasumi_file_view_bind_fd(int fd, const char *src_path, const char *target_path);
bool kasumi_file_view_lookup_maps(unsigned long target_ino, unsigned long target_dev,
				  unsigned long *spoofed_ino,
				  unsigned long *spoofed_dev,
				  char *spoofed_pathname,
				  size_t spoofed_pathname_size);
void kasumi_file_view_clear(void);
void kasumi_file_view_shutdown(void);

#endif /* _KASUMI_FILE_VIEW_H */
