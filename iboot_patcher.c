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
#include "ibootsup.h"
#include "structs.h"
#include "patch.h"
#include "util.h"

int
main (int argc, char *argv[])
{
	if(argc != 3) {
		printf("usage: %s [in] [out] (input must be unencrypted image3)\n", argv[0]);
		return -1;
	}

	assert (ibootsup_map_file (argv[1]) == 0);
	assert (ibootsup_dynapatch () == 0);
	assert (ibootsup_write_file (argv[2]) == 0);
	return 0;
}