/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
#ifndef KASUMI_FOP_BRIDGE_H
#define KASUMI_FOP_BRIDGE_H

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/types.h>

struct kasumi_fop_bridge_entry {
	const struct file_operations *ingress;
	const struct file_operations *live;
	const struct file_operations *orig;
	struct hlist_node node;
	bool registered;
};

int kasumi_fop_bridge_init(void);
void kasumi_fop_bridge_stop_new(void);
void kasumi_fop_bridge_exit(void);
bool kasumi_fop_bridge_capable(void);
bool kasumi_fop_bridge_register(struct kasumi_fop_bridge_entry *entry,
				const struct file_operations *ingress,
				const struct file_operations *live,
				const struct file_operations *orig);
void kasumi_fop_bridge_unregister(struct kasumi_fop_bridge_entry *entry);

#endif /* KASUMI_FOP_BRIDGE_H */
