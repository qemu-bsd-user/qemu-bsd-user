/*
 * Utility function to get QEMU's own process map
 *
 * Copyright (c) 2020 Linaro Ltd
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/selfmap.h"

#ifdef __FreeBSD__
#include <sys/sysctl.h>
#include <sys/user.h>

IntervalTreeRoot *read_self_maps(void)
{
    IntervalTreeRoot *root;
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, getpid()};
    size_t len;
    char *buf, *p;

    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) {
        return NULL;
    }

    /* Add some slack in case mappings change between calls. */
    len = len * 4 / 3;
    buf = g_malloc(len);
    if (sysctl(mib, 4, buf, &len, NULL, 0) < 0) {
        g_free(buf);
        return NULL;
    }

    root = g_new0(IntervalTreeRoot, 1);

    for (p = buf; p < buf + len; ) {
        struct kinfo_vmentry *kve = (struct kinfo_vmentry *)p;
        MapInfo *e;
        size_t path_len;

        if (kve->kve_structsize == 0) {
            break;
        }

        /* Skip guard/dead entries. */
        if (kve->kve_type != KVME_TYPE_GUARD &&
            kve->kve_type != KVME_TYPE_DEAD) {
            const char *path = NULL;

            if (kve->kve_path[0] != '\0') {
                path = kve->kve_path;
                path_len = strlen(path) + 1;
            } else {
                path_len = 0;
            }

            e = g_malloc0(sizeof(*e) + path_len);
            e->itree.start = kve->kve_start;
            e->itree.last = kve->kve_end - 1;
            e->offset = kve->kve_offset;
            e->is_read = (kve->kve_protection & KVME_PROT_READ) != 0;
            e->is_write = (kve->kve_protection & KVME_PROT_WRITE) != 0;
            e->is_exec = (kve->kve_protection & KVME_PROT_EXEC) != 0;
            e->is_priv = (kve->kve_flags & KVME_FLAG_COW) != 0;
            if (path_len) {
                e->path = memcpy(e + 1, path, path_len);
            }
            interval_tree_insert(&e->itree, root);
        }

        p += kve->kve_structsize;
    }

    g_free(buf);
    return root;
}

#else /* !__FreeBSD__ */

IntervalTreeRoot *read_self_maps(void)
{
    IntervalTreeRoot *root;
    gchar *maps, **lines;
    guint i, nlines;

    if (!g_file_get_contents("/proc/self/maps", &maps, NULL, NULL)) {
        return NULL;
    }

    root = g_new0(IntervalTreeRoot, 1);
    lines = g_strsplit(maps, "\n", 0);
    nlines = g_strv_length(lines);

    for (i = 0; i < nlines; i++) {
        gchar **fields = g_strsplit(lines[i], " ", 6);
        guint nfields = g_strv_length(fields);

        if (nfields > 4) {
            uint64_t start, end, offset, inode;
            unsigned dev_maj, dev_min;
            int errors = 0;
            const char *p;

            errors |= qemu_strtou64(fields[0], &p, 16, &start);
            errors |= qemu_strtou64(p + 1, NULL, 16, &end);
            errors |= qemu_strtou64(fields[2], NULL, 16, &offset);
            errors |= qemu_strtoui(fields[3], &p, 16, &dev_maj);
            errors |= qemu_strtoui(p + 1, NULL, 16, &dev_min);
            errors |= qemu_strtou64(fields[4], NULL, 10, &inode);

            if (!errors) {
                size_t path_len;
                MapInfo *e;

                if (nfields == 6) {
                    p = fields[5];
                    p += strspn(p, " ");
                    path_len = strlen(p) + 1;
                } else {
                    p = NULL;
                    path_len = 0;
                }

                e = g_malloc0(sizeof(*e) + path_len);

                e->itree.start = start;
                e->itree.last = end - 1;
                e->offset = offset;
                e->dev = makedev(dev_maj, dev_min);
                e->inode = inode;

                e->is_read  = fields[1][0] == 'r';
                e->is_write = fields[1][1] == 'w';
                e->is_exec  = fields[1][2] == 'x';
                e->is_priv  = fields[1][3] == 'p';

                if (path_len) {
                    e->path = memcpy(e + 1, p, path_len);
                }

                interval_tree_insert(&e->itree, root);
            }
        }
        g_strfreev(fields);
    }
    g_strfreev(lines);
    g_free(maps);

    return root;
}

#endif /* __FreeBSD__ */

/**
 * free_self_maps:
 * @root: an interval tree
 *
 * Free a tree of MapInfo structures.
 * Since we allocated each MapInfo in one chunk, we need not consider the
 * contents and can simply free each RBNode.
 */

static void free_rbnode(RBNode *n)
{
    if (n) {
        free_rbnode(n->rb_left);
        free_rbnode(n->rb_right);
        g_free(n);
    }
}

void free_self_maps(IntervalTreeRoot *root)
{
    if (root) {
        free_rbnode(root->rb_root.rb_node);
        g_free(root);
    }
}
