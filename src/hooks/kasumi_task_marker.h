/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
#ifndef _KASUMI_TASK_MARKER_H
#define _KASUMI_TASK_MARKER_H

#include <linux/types.h>

typedef bool (*kasumi_task_marker_uid_predicate_fn)(uid_t uid);

/* Predicate must be atomic/RCU-safe and independent of kasumi_enabled. */
int kasumi_task_marker_init(kasumi_task_marker_uid_predicate_fn predicate);
void kasumi_task_marker_start(void);
void kasumi_task_marker_exit(void);
void kasumi_task_marker_set_enabled(bool enabled);
void kasumi_task_marker_refresh(void);
void kasumi_task_marker_refresh_scopes(void);
void kasumi_task_marker_restrict_exclusive(void);
void kasumi_task_marker_reconcile_owned(bool release_all);
void kasumi_task_marker_reconcile_current(void);
bool kasumi_task_marker_available(void);
bool kasumi_task_marker_ready(void);
bool kasumi_task_marker_active(void);

#endif /* _KASUMI_TASK_MARKER_H */
