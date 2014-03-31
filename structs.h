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

#ifndef __STRUCTS_H
#define __STRUCTS_H

typedef enum
{
    DEVICE_BOOT_STAGE_SECUREROM = 0,
    DEVICE_BOOT_STAGE_DFU_EMULATION,
    DEVICE_BOOT_STAGE_IBOOT,
    DEVICE_BOOT_STAGE_DEVICE_OS
} device_boot_stage;

typedef enum
{
    CHIP_FAMILY_TYPE_DEVELOPMENT = 1,   /* 0b01 */
    CHIP_FAMILY_TYPE_PRODUCTION = 3 /* 0b11 */
} chip_family;

typedef enum
{
    FALSE,
    TRUE
} boolean_t;

struct device_information
{
    uint16_t chip_id;
    uint32_t chip_epoch;
    chip_family chip_family;
    uint32_t board_id;
    device_boot_stage boot_stage;
    void *device_usb_context;   /* Abstracted. */
};

struct iboot_interval {
    int low_bound, high_bound;
    int os_version;
};

struct kernel_interval {
    int low_bound, high_bound;
    float os_version;
};

struct generic_patch
{
    uint8_t *original;
    uint8_t *patched;
    int size;
    char* name;
};

struct patch_list
{
    struct patch_list *next;
    struct generic_patch patch;
};

struct patch_list_root
{
    struct patch_list *next;
    struct generic_patch patch;
    int total;
    char* name;
};

struct mapped_image {
    uint8_t* image;
    int size;
};

extern struct device_information device_information_context;

#define CHIP_ID_S5L8900X        0x8900
#define CHIP_ID_S5L8920X        0x8920
#define CHIP_ID_S5L8922X        0x8922
#define CHIP_ID_S5L8930X        0x8930
#define CHIP_ID_S5L8940X        0x8940
#define CHIP_ID_S5L8945X        0x8945
#define CHIP_ID_S5L8950X        0x8950
#define CHIP_ID_S5L8955X        0x8955
#define CHIP_ID_S5L8960X        0x8960
#define CHIP_ID_S5L8720X        0x8720
#define CHIP_ID_S5L8747X        0x8747
#define CHIP_ID_MASK            0xFF00

#define IS_IDEVICE_8900(chip_id)    (((chip_id & CHIP_ID_MASK) == 0x8900))
#define IS_IDEVICE_8700(chip_id)    (((chip_id & CHIP_ID_MASK) == 0x8700))

#endif /* __STRUCTS_H */
