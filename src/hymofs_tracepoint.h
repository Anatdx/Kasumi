/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _HYMOFS_TRACEPOINT_H
#define _HYMOFS_TRACEPOINT_H

int hymofs_tracepoint_path_init(void);
void hymofs_tracepoint_path_exit(void);
int hymofs_tracepoint_path_registered(void);
int hymofs_tracepoint_getfd_registered(void);

#endif /* _HYMOFS_TRACEPOINT_H */
