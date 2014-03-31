/*-
 * Copyright 2013, winocm <winocm@icloud.com>
 * Copyright 2013, iH8sn0w.
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
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <unistd.h>
#include <fcntl.h>
#include <err.h>

#include <assert.h>
#include "structs.h"
#include "patch.h"
#include "util.h"

#define IBOOT_DEFAULT_BOOTARGS	"rd=md0 nand-enable-reformat=1 -progress"
#define IBOOT_DEFAULT_PWNARGS	"-v amfi=0xff cs_enforcement_disable=1  "
C_ASSERT (sizeof (IBOOT_DEFAULT_PWNARGS) == sizeof (IBOOT_DEFAULT_BOOTARGS));

#define IBOOT_IOS7_SIGPATTERN		"\xAB\x29\x46\x32\x46"
#define IBOOT_IOS7_SIGLEN			5
#define IBOOT_IOS7_BA_COND			"\x00\x2D\x7E\x4C\x18\xBF"
#define IBOOT_IOS7_BA_LEN			6
#define IBOOT_IOS7_IMG3PATCH_PATCH	"\xC0\x46"
#define IBOOT_IOS7_IMG3PATCH_PLEN	2
#define IBOOT_IOS7_BA_COND_PATCH	"\xC0\x46\xC0\x46\xC0\x46"
#define	IBOOT_IOS7_BA_COND_LEN		6
#define IBOOT_IOS7_SIGPATCH			"\x00\x20\x18\x60"
#define IBOOT_IOS7_SIGPATCH_LEN		4
#define IBOOT_IOS7_IMG3PATCH		"\x46\xF2\x33\x72\x16\x20\xC4\xF6\x6D\x12"
#define IBOOT_IOS7_IMG3PATCH_LEN	10

#define IBOOT_IOS_LEGACY_PATCH	"\x00\x20\x00\x20"
#define IBOOT_IOS_LEGACY_PLEN	4
#define IBOOT_IOS_RSA_PATTERN	"\x8C\xEA\x02\x02"
#define IBOOT_IOS_RSA_LEN		4
#define IBOOT_IOS_BA_COND		"\x00\x29\x14\xBF\x1C\x46\x14\x46\x10\x22"
#define IBOOT_IOS_BA_LEN		10
#define IBOOT_IOS_BA_PATCH		"\x1C\x46\x1C\x46\x1C\x46\x1C\x46\x10\x22"
#define IBOOT_IOS_BA_PLEN		10

#define ARM_BRANCH_OPCODE		"\x0e\x00\x00\xea"
#define OPCODE_LENGTH			4
#define IBOOT_IMAGE_VERSION		0x280

static struct iboot_interval intervals[] = {
	{320, 590, 2},
	{594, 817, 3},
	{889, 1072, 4},
	{1219, 1220, 5},
	{1537, 1538, 6},
	{1940, 1941, 7},
	{0, 0, -1},
};

static uint32_t ibootsup_image3_tags[9] = { 'SDOM', 'PROD', 'CHIP', 'TYPE', 'SEPO', 'CEPO', 'BORD', 'ECID',
	'OVRD'
};

static struct mapped_image current_image;

static void *pattern_search (void *addr, int len, int pattern, int mask, int step);
static void *ldr_search_up (const void *start_addr, int len);
static void *ldr32_search_up (const void *start_addr, int len);
static void *bl_search_down (void *p, int l);
static void *bl_search_up (void *p, int l);
static void *resolve_bl32 (const void *bl);
static void *locate_ldr (const void *startAddr);
static boolean_t ibootsup_verify_arm_image (void);
static int ibootsup_get_version (void);
static int ibootsup_get_ios_version (void);
static void ibootsup_patch_ios_old_iboot (void);
static void ibootsup_patch_ios7_iboot (void);
static void ibootsup_patch_iboot (void);

static void *
pattern_search (void *addr, int len, int pattern, int mask, int step)
{
	char *caddr = (char *) (addr);
	int i;
	if (len <= 0)
		return NULL;

	if (step < 0) {
		len = -len;
		len &= ~-(step + 1);
	}
	else {
		len &= ~(step - 1);
	}

	for (i = 0; i != len; i += step) {
		int x = *(int *) (caddr + i);
		if ((x & mask) == pattern) {
			return (void *) (caddr + i);
		}
	}
	return NULL;
}

static void *
ldr_search_up (const void *start_addr, int len)
{
	// LDR pattern is xx xx 48 xx ( 00 00 f8 00 )
	return pattern_search (start_addr, len, 0x00004800, 0x0000F800, -2);
}

static void *
ldr32_search_up (const void *start_addr, int len)
{
	// LDR32 pattern is DF F8 xx xx
	return pattern_search (start_addr, len, 0x0000F8DF, 0x0000FFFF, -2);
}

static void *
bl_search_down (void *p, int l)
{
	return pattern_search (p, l, 0xD000F000, 0xD000F800, 2);
}

static void *
bl_search_up (void *p, int l)
{
	return pattern_search (p, l, 0xD000F000, 0xD000F800, -2);
}

static void *
resolve_bl32 (const void *bl)
{
	typedef unsigned short uint16_t;
	typedef int int32_t;
	union
	{
		uint16_t value;

		struct
		{
			uint16_t immediate:10;
			uint16_t s:1;
			  uint16_t:5;
		};
	} bits = {
	*(uint16_t *) bl};

	union
	{
		uint16_t value;

		struct
		{
			uint16_t immediate:11;
			uint16_t j2:1;
			uint16_t x:1;
			uint16_t j1:1;
			  uint16_t:2;
		};
	} exts = {
	((uint16_t *) bl)[1]};

	int32_t jump = 0;
	jump |= bits.s << 24;
	jump |= (~(bits.s ^ exts.j1) & 0x1) << 23;
	jump |= (~(bits.s ^ exts.j2) & 0x1) << 22;
	jump |= bits.immediate << 12;
	jump |= exts.immediate << 1;
	jump |= exts.x;
	jump <<= 7;
	jump >>= 7;
	return (void *) ((int) bl + 4 + jump);
}

static void *
locate_ldr (const void *startAddr)
{
	int xref_target = (int) startAddr;
	int i = xref_target;
	int min_addr = xref_target - 0x1000;
	while (1) {
		i = (int) ldr32_search_up ((void *) i, i - min_addr);
		if (i == 0) {
			break;
		}
		int dw = *(int *) i;
		int ldr_target = ((i + 4) & ~3) + ((dw >> 16) & 0xfff);
		if (ldr_target == xref_target) {
			return (void *) i;
		}
		i -= 4;
	}
	i = xref_target;
	min_addr = xref_target - 0x420;
	while (1) {
		i = (int) ldr_search_up ((void *) i, i - min_addr);
		if (i == 0) {
			break;
		}
		int dw = *(int *) i;
		int ldr_target = ((i + 4) & ~3) + ((dw & 0xff) << 2);
		if (ldr_target == xref_target) {
			return (void *) i;
		}
		i -= 2;
	}
	return 0;
}

static boolean_t
ibootsup_verify_arm_image (void)
{
	if (!memcmp (current_image.image, ARM_BRANCH_OPCODE, OPCODE_LENGTH))
		return TRUE;
	return FALSE;
}

static int
ibootsup_get_version (void)
{
	int off = IBOOT_IMAGE_VERSION + sizeof ("iBoot-") - 1;	/* Accomodate for '\0' */
	return atoi ((char *) current_image.image + off);
}

static int
ibootsup_get_ios_version (void)
{
	int current_version = ibootsup_get_version ();
	struct iboot_interval *interval = &intervals[0];
	while (interval->os_version != -1) {
		if (current_version >= interval->low_bound && current_version <= interval->high_bound)
			return interval->os_version;
		interval++;
	}
	err (-1, "failed to match iBoot version, probably too new/old?");
	return 0;
}

int
ibootsup_map_buffer (uint8_t * buf, int size)
{
	current_image.image = buf;
	current_image.size = size;

	if (!ibootsup_verify_arm_image ()) {
		return -EBADF;
	}

	return 0;
}

int
ibootsup_map_file (const char *filename)
{
	struct stat buf;
	FILE *fp = fopen (filename, "rb");

	if (!fp)
		return -ENOENT;
	if (stat (filename, &buf) > 0)
		return -ENOENT;

	current_image.image = (uint8_t *) _xmalloc (buf.st_size);
	current_image.size = buf.st_size;
	fread ((void *) current_image.image, buf.st_size, 1, fp);
	fclose (fp);

	if (!ibootsup_verify_arm_image ()) {
		free (current_image.image);
		return -EBADF;
	}

	return 0;
}

static inline uint8_t *
ibootsup_off2pat_patch (int offset, uint8_t * patch, int bufsize, int patchsize)
{
	uint8_t *buffer = (uint8_t *) _xmalloc (bufsize);
	memcpy (buffer, current_image.image + offset, bufsize);
	memcpy (buffer, patch, patchsize);
	return buffer;
}

static void
ibootsup_patch_ios_old_iboot (void)
{
	int i = 0, tag = 0, rsaoff = 0, bootargoff = 0, bacondoff = 0;

	/*
	 * Initialize patch list. 
	 */
	patch_list_initialize ();

	/*
	 * Pass zero, scan file for image3 tags. 
	 */
	for (i = 0; i < current_image.size; i++) {
		/*
		 * Overwrite conditional
		 */
		if (!memcmp (current_image.image + i, IBOOT_IOS_BA_COND, IBOOT_IOS_BA_LEN))
			bacondoff = i;

		/*
		 * Overwrite with boot-arguments. 
		 */
		if (!memcmp (current_image.image + i, IBOOT_DEFAULT_BOOTARGS, sizeof (IBOOT_DEFAULT_BOOTARGS)))
			bootargoff = i;

		for (tag = 0; tag < (sizeof (ibootsup_image3_tags) / sizeof (uint32_t)); tag++) {
			if (!memcmp (current_image.image + i, &ibootsup_image3_tags[tag], 4)) {
				void *ldr = locate_ldr (current_image.image + i);
				void *bl = bl_search_down (ldr, 0x200);
				uint32_t off = (uint32_t) bl - (uint32_t) current_image.image;
				printf ("%x tag check: %x\n", ibootsup_image3_tags[tag], off);
				patch_list_add_patch ("Image3 Tag Check", current_image.image + off, ibootsup_off2pat_patch (off, (uint8_t *) IBOOT_IOS_LEGACY_PATCH, 16, IBOOT_IOS_LEGACY_PLEN), 16);
			}
		}

		/*
		 * RSA offset. 
		 */
		if (!memcmp (current_image.image + i, IBOOT_IOS_RSA_PATTERN, IBOOT_IOS_RSA_LEN))
			rsaoff = i + 0x10;
	}

	if (!rsaoff) {
		warn ("RSA check missing???");
		return;
	}

	if (!bootargoff || !bacondoff) {
		warn ("boot-argument check missing, is this a proper iBoot?");
	}

	/*
	 * RSA check.
	 */
	printf ("RSA check at %x.\n", rsaoff);
	patch_list_add_patch ("RSA patch", current_image.image + rsaoff, ibootsup_off2pat_patch (rsaoff, (uint8_t *) IBOOT_IOS_LEGACY_PATCH, 16, IBOOT_IOS_LEGACY_PLEN), 16);
	printf ("Boot-arg conditional at %x.\n", bacondoff);
	if (bootargoff) {
		patch_list_add_patch ("BootArgs", current_image.image + bootargoff, ibootsup_off2pat_patch (bootargoff, (uint8_t *) IBOOT_DEFAULT_PWNARGS, sizeof (IBOOT_DEFAULT_BOOTARGS), sizeof (IBOOT_DEFAULT_BOOTARGS)), sizeof (IBOOT_DEFAULT_BOOTARGS));
	}
	if (bacondoff) {
		patch_list_add_patch ("BootArgs Conditional", current_image.image + bacondoff, ibootsup_off2pat_patch (bacondoff, (uint8_t *) IBOOT_IOS_BA_PATCH, 16, IBOOT_IOS_BA_PLEN), 16);
	}

	/*
	 * Dump listing. 
	 */
	patch_list_iterate ();
}

static void
ibootsup_patch_ios7_iboot (void)
{
	int i = 0, sigoff = 0, bootargoff = 0, bacondoff = 0, img3off = 0;

	/*
	 * Pass zero, scan file for signature check. 
	 */
	for (i = 0; i < current_image.size; i++) {
		/*
		 * Patch to 00 20 18 60 
		 */
		if (!memcmp (current_image.image + i, IBOOT_IOS7_SIGPATTERN, IBOOT_IOS7_SIGLEN))
			sigoff = i + IBOOT_IOS7_SIGLEN;

		/*
		 * Overwrite with boot-arguments. 
		 */
		if (!memcmp (current_image.image + i, IBOOT_DEFAULT_BOOTARGS, sizeof (IBOOT_DEFAULT_BOOTARGS)))
			bootargoff = i;

		/*
		 * Conditional to allow injection of boot-args with/without RAM disk. 
		 */
		if (!memcmp (current_image.image + i, IBOOT_IOS7_BA_COND, IBOOT_IOS7_BA_LEN))
			bacondoff = i;

		/*
		 * Allow stock image3 files. 
		 */
		if (!memcmp (current_image.image + i, IBOOT_IOS7_IMG3PATCH, IBOOT_IOS7_IMG3PATCH_LEN))
			img3off = i + 0x18;
	}

	printf ("Signature offset at %x.\n", sigoff);
	printf ("Boot-arg offset at %x.\n", bootargoff);
	printf ("Boot-arg-conditional offset at %x.\n", bacondoff);
	printf ("Image3-signature at %x\n", img3off);

	if (!sigoff || !img3off) {
		warn ("finding one of the core patches FAILED\n");
		return;
	}

	/*
	 * (Re)initialize patch list and add patches. Convert the offsets into bytepatterns. 
	 */
	patch_list_initialize ();
	patch_list_add_patch ("Image3 Stock Image Load", current_image.image + img3off, ibootsup_off2pat_patch (img3off, (uint8_t *) IBOOT_IOS7_IMG3PATCH_PATCH, 16, IBOOT_IOS7_IMG3PATCH_PLEN), 16);
	patch_list_add_patch ("Signature", current_image.image + sigoff, ibootsup_off2pat_patch (sigoff, (uint8_t *) IBOOT_IOS7_SIGPATCH, 16, IBOOT_IOS7_SIGPATCH_LEN), 16);
	if (bootargoff) {
		patch_list_add_patch ("BootArgs", current_image.image + bootargoff, ibootsup_off2pat_patch (bootargoff, (uint8_t *) IBOOT_DEFAULT_PWNARGS, sizeof (IBOOT_DEFAULT_BOOTARGS), sizeof (IBOOT_DEFAULT_BOOTARGS)), sizeof (IBOOT_DEFAULT_BOOTARGS));
	}
	if (bacondoff) {
		patch_list_add_patch ("BootArgs Conditional", current_image.image + bacondoff, ibootsup_off2pat_patch (bacondoff, (uint8_t *) IBOOT_IOS7_BA_COND_PATCH, 16, IBOOT_IOS7_BA_COND_LEN), 16);
	}

	patch_list_iterate ();
}

static void
ibootsup_patch_iboot (void)
{
	struct patch_list *head, *iter;
	int total_patches, i = 0, j = 0;
	double progress = 0.0;
	printf ("Patching iBoot *NOW*...\n");

	if (patch_list_get_head (&head, &total_patches)) {
		warn ("failed to get patch list head\n");
		return;
	}

	/*
	 * Patch it!
	 */
	for (iter = head, i = 0; i < total_patches; iter = iter->next, i++) {
		for (j = 0; j < current_image.size; j++) {
			if (!memcmp (current_image.image + j, iter->patch.original, iter->patch.size)) {
				memcpy (current_image.image + j, iter->patch.patched, iter->patch.size);
				progress = ((i + 1) / (double) total_patches) * 100.0;
				printf ("%4.1f%% done. [(%d/%d) %-32.32s]\r", progress, i + 1, total_patches, iter->patch.name);
				fflush (stdout);
			}
		}
	}
	printf ("\n");
}

int
ibootsup_dynapatch (void)
{
	printf ("starting dynapatch...\n");

	switch (ibootsup_get_ios_version ()) {
	case 4:					/* iOS 4. */
		ibootsup_patch_ios_old_iboot ();
		break;
	case 7:					/* iOS 7. */
		ibootsup_patch_ios7_iboot ();
		break;
	default:
		warn ("iOS %d not supported yet for iBoot patcher", ibootsup_get_ios_version ());
		return -1;
	}

	ibootsup_patch_iboot ();

	return 0;
}

int
ibootsup_write_file (const char *filename)
{
	struct stat buf;
	FILE *fp = fopen (filename, "wb");

	if (!fp)
		return -ENOENT;
	if (stat (filename, &buf) > 0)
		return -ENOENT;

	fwrite ((void *) current_image.image, current_image.size, 1, fp);
	fclose (fp);

	free (current_image.image);
	current_image.image = NULL;
	current_image.size = 0;

	return 0;
}