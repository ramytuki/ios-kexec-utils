/*-
 * Copyright 2013, winocm <winocm@icloud.com>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * $Id$
 */

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <err.h>

#include <assert.h>
#include "structs.h"
#include "patch.h"
#include "util.h"

static boolean_t patch_list_initialized = FALSE;

static struct patch_list_root patch_list_store;
static struct patch_list *patch_list_head;
static struct patch_list *patch_list_current_node;

static struct patch_list *patch_list_object_allocate (void);
static void patch_list_add_object (struct patch_list *);

static inline char *
patch_list_dump_hex (uint8_t * p, int size)
{
	int i = 0, fixed_up = size * 2 + 1;
	char *buffer = _xmalloc (fixed_up);
	for (i = 0; i < size; i++) {
		snprintf (buffer, fixed_up, "%s%02X", buffer, p[i]);
	}
	buffer[fixed_up - 1] = '\0';
	return buffer;
}

static struct patch_list *
patch_list_object_allocate (void)
{
	return (struct patch_list *) _xmalloc (sizeof (struct patch_list));
}

static void
patch_list_add_object (struct patch_list *object)
{
	patch_list_current_node->next = object;
	patch_list_current_node = object;
	if (patch_list_store.total == 0)
		patch_list_head = patch_list_current_node;
	patch_list_store.total++;
	return;
}

void
patch_list_iterate (void)
{
	int i;
	struct patch_list *iter = patch_list_head;
	printf ("Total patches: %d\n", patch_list_store.total);
	for (iter = patch_list_head, i = 0; i < patch_list_store.total; iter = iter->next, i++) {
		printf ("Patch at %p\nName:          %s\nSearch for:    %s\nReplace with:  %s\nSize:          %d\n",
				iter, iter->patch.name, patch_list_dump_hex (iter->patch.original, iter->patch.size),
				patch_list_dump_hex (iter->patch.patched, iter->patch.size), iter->patch.size);
	}
}

int
patch_list_get_head(struct patch_list** object_export, int* size)
{
	if (!patch_list_initialized)
		return -EPERM;

	*object_export = patch_list_head;
	*size = patch_list_store.total;

	return 0;
}

int
patch_list_initialize (void)
{
	bzero (&patch_list_store, sizeof (struct patch_list_root));
	patch_list_head = (struct patch_list *) &patch_list_store;
	patch_list_current_node = patch_list_head;
	patch_list_initialized = TRUE;
	return 0;
}

int
patch_list_add_patch (const char *name, uint8_t * original, uint8_t * patched, int size)
{
	struct patch_list *object;

	if (!patch_list_initialized)
		return -EACCES;

	object = patch_list_object_allocate ();

	/*
	 * We don't verify the size of the objects being patched, you should do
	 * that.
	 */
	object->patch.original = original;
	object->patch.patched = patched;
	object->patch.name = strdup (name);
	object->patch.size = size;
	object->next = object;

	patch_list_add_object (object);

	return 0;
}