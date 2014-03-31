/*
 * Copyright 2014, winocm. <winocm@icloud.com>
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
/*
 * multi_kloader
 * Requires iOS 6.x or 7.x. (This version only.)
 * 
 * Designed to chain both iBSS + iBEC, not just one.
 *
 * Remap addresses:
 * 0x7fe00000 -> 0x9fe00000 (0x5fe00000) iBSS (jump-to)
 * 0x7fd00000 -> 0x9fd00000 (0x5fd00000) iBEC
 *
 * xcrun -sdk iphoneos clang kloader.c -arch armv7 -framework IOKit -framework CoreFoundation -no-integrated-as \
 *     -DINLINE_IT_ALL=1 -Wall -o kloader -miphoneos-version-min=6.0; ldid -Stfp0.plist kloader
 */

#include <mach/mach.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <err.h>
#include <signal.h>

typedef mach_port_t io_service_t;
extern mach_port_t kIOMasterPortDefault;
extern mach_port_t IOPMFindPowerManagement(mach_port_t);
extern kern_return_t IOPMSleepSystem(mach_port_t);

/*
 * ARM page bits for L1 sections.
 */
#define L1_SHIFT            20  /* log2(1MB) */

#define L1_SECT_PROTO        (1 << 1)   /* 0b10 */

#define L1_SECT_B_BIT        (1 << 2)
#define L1_SECT_C_BIT        (1 << 3)

#define L1_SECT_SORDER       (0)    /* 0b00, not cacheable, strongly ordered. */
#define L1_SECT_SH_DEVICE    (L1_SECT_B_BIT)
#define L1_SECT_WT_NWA       (L1_SECT_C_BIT)
#define L1_SECT_WB_NWA       (L1_SECT_B_BIT | L1_SECT_C_BIT)
#define L1_SECT_S_BIT        (1 << 16)

#define L1_SECT_AP_URW       (1 << 10) | (1 << 11)
#define L1_SECT_PFN(x)       (x & 0xFFF00000)

#define L1_SECT_DEFPROT      (L1_SECT_AP_URW)
#define L1_SECT_DEFCACHE     (L1_SECT_SORDER)

#define L1_PROTO_TTE(paddr)  (L1_SECT_PFN(paddr) | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE | L1_SECT_PROTO)

#define PFN_SHIFT            2
#define TTB_OFFSET(vaddr)    ((vaddr >> L1_SHIFT) << PFN_SHIFT)

/*
 * RAM physical base begin. 
 */
#define S5L8930_PHYS_OFF    0x40000000
#define S5L8940_PHYS_OFF    0x80000000  /* Note: RAM base is identical for 8940-8955. */

uint32_t PHYS_OFF = S5L8930_PHYS_OFF;

/*
 * Shadowmap begin and end. 15MB of shadowmap is enough for the kernel.
 * We don't need to invalidate unified D/I TLB or any cache lines
 * since the kernel is mapped as writethrough memory, and these
 * addresses are guaranteed to not be translated.
 * (Accesses will cause segmentation faults due to failure on L1 translation.)
 *
 * Clear the shadowmappings when done owning the kernel.
 *
 * 0x7ff0'0000 is also below the limit for vm_read and such, so that's also *great*.
 * (2048 bytes)
 */
#define SHADOWMAP_BEGIN          0x7f000000
#define SHADOWMAP_END            0x7ff00000
#define SHADOWMAP_GRANULARITY    0x00100000

#define SHADOWMAP_SIZE_BYTES    (SHADOWMAP_END - SHADOWMAP_BEGIN)

#define SHADOWMAP_BEGIN_OFF     TTB_OFFSET(SHADOWMAP_BEGIN)
#define SHADOWMAP_END_OFF       TTB_OFFSET(SHADOWMAP_END)
#define SHADOWMAP_SIZE          (SHADOWMAP_END_OFF - SHADOWMAP_BEGIN_OFF)

#define SHADOWMAP_BEGIN_IDX     (SHADOWMAP_BEGIN_OFF >> PFN_SHIFT)
#define SHADOWMAP_END_IDX       (SHADOWMAP_END_OFF >> PFN_SHIFT)

#define TTB_SIZE                4096
#define DEFAULT_KERNEL_SLIDE    0x80000000

static mach_port_t kernel_task = 0;
static uint32_t ttb_template[TTB_SIZE] = { };

static void *ttb_template_ptr = &ttb_template[0];
static uint32_t kernel_base = DEFAULT_KERNEL_SLIDE;

typedef struct pmap_partial_t {
    uint32_t tte_virt;
    uint32_t tte_phys;
    /*
     * ... 
     */
} pmap_partial_t;

/* --- planetbeing patchfinder --- */

static uint32_t bit_range(uint32_t x, int start, int end)
{
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

static uint32_t ror(uint32_t x, int places)
{
    return (x >> places) | (x << (32 - places));
}

static int thumb_expand_imm_c(uint16_t imm12)
{
    if (bit_range(imm12, 11, 10) == 0) {
        switch (bit_range(imm12, 9, 8)) {
        case 0:
            return bit_range(imm12, 7, 0);
        case 1:
            return (bit_range(imm12, 7, 0) << 16) | bit_range(imm12, 7, 0);
        case 2:
            return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 8);
        case 3:
            return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 16) | (bit_range(imm12, 7, 0) << 8) | bit_range(imm12, 7, 0);
        default:
            return 0;
        }
    } else {
        uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
        return ror(unrotated_value, bit_range(imm12, 11, 7));
    }
}

static int insn_is_32bit(uint16_t * i)
{
    return (*i & 0xe000) == 0xe000 && (*i & 0x1800) != 0x0;
}

static int insn_is_bl(uint16_t * i)
{
    if ((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd000) == 0xd000)
        return 1;
    else if ((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd001) == 0xc000)
        return 1;
    else
        return 0;
}

static uint32_t insn_bl_imm32(uint16_t * i)
{
    uint16_t insn0 = *i;
    uint16_t insn1 = *(i + 1);
    uint32_t s = (insn0 >> 10) & 1;
    uint32_t j1 = (insn1 >> 13) & 1;
    uint32_t j2 = (insn1 >> 11) & 1;
    uint32_t i1 = ~(j1 ^ s) & 1;
    uint32_t i2 = ~(j2 ^ s) & 1;
    uint32_t imm10 = insn0 & 0x3ff;
    uint32_t imm11 = insn1 & 0x7ff;
    uint32_t imm32 = (imm11 << 1) | (imm10 << 12) | (i2 << 22) | (i1 << 23) | (s ? 0xff000000 : 0);
    return imm32;
}

static int insn_is_b_conditional(uint16_t * i)
{
    return (*i & 0xF000) == 0xD000 && (*i & 0x0F00) != 0x0F00 && (*i & 0x0F00) != 0xE;
}

static int insn_is_b_unconditional(uint16_t * i)
{
    if ((*i & 0xF800) == 0xE000)
        return 1;
    else if ((*i & 0xF800) == 0xF000 && (*(i + 1) & 0xD000) == 9)
        return 1;
    else
        return 0;
}

static int insn_is_ldr_literal(uint16_t * i)
{
    return (*i & 0xF800) == 0x4800 || (*i & 0xFF7F) == 0xF85F;
}

static int insn_ldr_literal_rt(uint16_t * i)
{
    if ((*i & 0xF800) == 0x4800)
        return (*i >> 8) & 7;
    else if ((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

static int insn_ldr_literal_imm(uint16_t * i)
{
    if ((*i & 0xF800) == 0x4800)
        return (*i & 0xF) << 2;
    else if ((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) & 0xFFF) * (((*i & 0x0800) == 0x0800) ? 1 : -1);
    else
        return 0;
}

// TODO: More encodings
static int insn_is_ldr_imm(uint16_t * i)
{
    uint8_t opA = bit_range(*i, 15, 12);
    uint8_t opB = bit_range(*i, 11, 9);

    return opA == 6 && (opB & 4) == 4;
}

static int insn_ldr_imm_rt(uint16_t * i)
{
    return (*i & 7);
}

static int insn_ldr_imm_rn(uint16_t * i)
{
    return ((*i >> 3) & 7);
}

static int insn_ldr_imm_imm(uint16_t * i)
{
    return ((*i >> 6) & 0x1F);
}

// TODO: More encodings
static int insn_is_ldrb_imm(uint16_t * i)
{
    return (*i & 0xF800) == 0x7800;
}

static int insn_ldrb_imm_rt(uint16_t * i)
{
    return (*i & 7);
}

static int insn_ldrb_imm_rn(uint16_t * i)
{
    return ((*i >> 3) & 7);
}

static int insn_ldrb_imm_imm(uint16_t * i)
{
    return ((*i >> 6) & 0x1F);
}

static int insn_is_ldr_reg(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x5800)
        return 1;
    else if ((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return 1;
    else
        return 0;
}

static int insn_ldr_reg_rn(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x5800)
        return (*i >> 3) & 0x7;
    else if ((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*i & 0xF);
    else
        return 0;
}

int insn_ldr_reg_rt(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x5800)
        return *i & 0x7;
    else if ((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

int insn_ldr_reg_rm(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x5800)
        return (*i >> 6) & 0x7;
    else if ((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return *(i + 1) & 0xF;
    else
        return 0;
}

static int insn_ldr_reg_lsl(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x5800)
        return 0;
    else if ((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*(i + 1) >> 4) & 0x3;
    else
        return 0;
}

static int insn_is_add_reg(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x1800)
        return 1;
    else if ((*i & 0xFF00) == 0x4400)
        return 1;
    else if ((*i & 0xFFE0) == 0xEB00)
        return 1;
    else
        return 0;
}

static int insn_add_reg_rd(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x1800)
        return (*i & 7);
    else if ((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4);
    else if ((*i & 0xFFE0) == 0xEB00)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_add_reg_rn(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x1800)
        return ((*i >> 3) & 7);
    else if ((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4);
    else if ((*i & 0xFFE0) == 0xEB00)
        return (*i & 0xF);
    else
        return 0;
}

static int insn_add_reg_rm(uint16_t * i)
{
    if ((*i & 0xFE00) == 0x1800)
        return (*i >> 6) & 7;
    else if ((*i & 0xFF00) == 0x4400)
        return (*i >> 3) & 0xF;
    else if ((*i & 0xFFE0) == 0xEB00)
        return *(i + 1) & 0xF;
    else
        return 0;
}

static int insn_is_movt(uint16_t * i)
{
    return (*i & 0xFBF0) == 0xF2C0 && (*(i + 1) & 0x8000) == 0;
}

static int insn_movt_rd(uint16_t * i)
{
    return (*(i + 1) >> 8) & 0xF;
}

static int insn_movt_imm(uint16_t * i)
{
    return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
}

static int insn_is_mov_imm(uint16_t * i)
{
    if ((*i & 0xF800) == 0x2000)
        return 1;
    else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return 1;
    else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return 1;
    else
        return 0;
}

static int insn_mov_imm_rd(uint16_t * i)
{
    if ((*i & 0xF800) == 0x2000)
        return (*i >> 8) & 7;
    else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_mov_imm_imm(uint16_t * i)
{
    if ((*i & 0xF800) == 0x2000)
        return *i & 0xF;
    else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
    else
        return 0;
}

static int insn_is_cmp_imm(uint16_t * i)
{
    if ((*i & 0xF800) == 0x2800)
        return 1;
    else if ((*i & 0xFBF0) == 0xF1B0 && (*(i + 1) & 0x8F00) == 0x0F00)
        return 1;
    else
        return 0;
}

static int insn_cmp_imm_rn(uint16_t * i)
{
    if ((*i & 0xF800) == 0x2800)
        return (*i >> 8) & 7;
    else if ((*i & 0xFBF0) == 0xF1B0 && (*(i + 1) & 0x8F00) == 0x0F00)
        return *i & 0xF;
    else
        return 0;
}

static int insn_cmp_imm_imm(uint16_t * i)
{
    if ((*i & 0xF800) == 0x2800)
        return *i & 0xFF;
    else if ((*i & 0xFBF0) == 0xF1B0 && (*(i + 1) & 0x8F00) == 0x0F00)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else
        return 0;
}

static int insn_is_and_imm(uint16_t * i)
{
    return (*i & 0xFBE0) == 0xF000 && (*(i + 1) & 0x8000) == 0;
}

static int insn_and_imm_rn(uint16_t * i)
{
    return *i & 0xF;
}

static int insn_and_imm_rd(uint16_t * i)
{
    return (*(i + 1) >> 8) & 0xF;
}

static int insn_and_imm_imm(uint16_t * i)
{
    return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
}

static int insn_is_push(uint16_t * i)
{
    if ((*i & 0xFE00) == 0xB400)
        return 1;
    else if (*i == 0xE92D)
        return 1;
    else if (*i == 0xF84D && (*(i + 1) & 0x0FFF) == 0x0D04)
        return 1;
    else
        return 0;
}

static int insn_push_registers(uint16_t * i)
{
    if ((*i & 0xFE00) == 0xB400)
        return (*i & 0x00FF) | ((*i & 0x0100) << 6);
    else if (*i == 0xE92D)
        return *(i + 1);
    else if (*i == 0xF84D && (*(i + 1) & 0x0FFF) == 0x0D04)
        return 1 << ((*(i + 1) >> 12) & 0xF);
    else
        return 0;
}

static int insn_is_preamble_push(uint16_t * i)
{
    return insn_is_push(i) && (insn_push_registers(i) & (1 << 14)) != 0;
}

static int insn_is_str_imm(uint16_t * i)
{
    if ((*i & 0xF800) == 0x6000)
        return 1;
    else if ((*i & 0xF800) == 0x9000)
        return 1;
    else if ((*i & 0xFFF0) == 0xF8C0)
        return 1;
    else if ((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return 1;
    else
        return 0;
}

static int insn_str_imm_postindexed(uint16_t * i)
{
    if ((*i & 0xF800) == 0x6000)
        return 1;
    else if ((*i & 0xF800) == 0x9000)
        return 1;
    else if ((*i & 0xFFF0) == 0xF8C0)
        return 1;
    else if ((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) >> 10) & 1;
    else
        return 0;
}

static int insn_str_imm_wback(uint16_t * i)
{
    if ((*i & 0xF800) == 0x6000)
        return 0;
    else if ((*i & 0xF800) == 0x9000)
        return 0;
    else if ((*i & 0xFFF0) == 0xF8C0)
        return 0;
    else if ((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) >> 8) & 1;
    else
        return 0;
}

static int insn_str_imm_imm(uint16_t * i)
{
    if ((*i & 0xF800) == 0x6000)
        return (*i & 0x07C0) >> 4;
    else if ((*i & 0xF800) == 0x9000)
        return (*i & 0xFF) << 2;
    else if ((*i & 0xFFF0) == 0xF8C0)
        return (*(i + 1) & 0xFFF);
    else if ((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) & 0xFF);
    else
        return 0;
}

static int insn_str_imm_rt(uint16_t * i)
{
    if ((*i & 0xF800) == 0x6000)
        return (*i & 7);
    else if ((*i & 0xF800) == 0x9000)
        return (*i >> 8) & 7;
    else if ((*i & 0xFFF0) == 0xF8C0)
        return (*(i + 1) >> 12) & 0xF;
    else if ((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

static int insn_str_imm_rn(uint16_t * i)
{
    if ((*i & 0xF800) == 0x6000)
        return (*i >> 3) & 7;
    else if ((*i & 0xF800) == 0x9000)
        return 13;
    else if ((*i & 0xFFF0) == 0xF8C0)
        return (*i & 0xF);
    else if ((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*i & 0xF);
    else
        return 0;
}

// Given an instruction, search backwards until an instruction is found matching the specified criterion.
static uint16_t *find_last_insn_matching(uint32_t region, uint8_t * kdata, size_t ksize, uint16_t * current_instruction, int (*match_func) (uint16_t *))
{
    while ((uintptr_t) current_instruction > (uintptr_t) kdata) {
        if (insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3)) {
            current_instruction -= 2;
        } else {
            --current_instruction;
        }

        if (match_func(current_instruction)) {
            return current_instruction;
        }
    }

    return NULL;
}

// Given an instruction and a register, find the PC-relative address that was stored inside the register by the time the instruction was reached.
static uint32_t find_pc_rel_value(uint32_t region, uint8_t * kdata, size_t ksize, uint16_t * insn, int reg)
{
    // Find the last instruction that completely wiped out this register
    int found = 0;
    uint16_t *current_instruction = insn;
    while ((uintptr_t) current_instruction > (uintptr_t) kdata) {
        if (insn_is_32bit(current_instruction - 2)) {
            current_instruction -= 2;
        } else {
            --current_instruction;
        }

        if (insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg) {
            found = 1;
            break;
        }

        if (insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg) {
            found = 1;
            break;
        }
    }

    if (!found)
        return 0;

    // Step through instructions, executing them as a virtual machine, only caring about instructions that affect the target register and are commonly used for PC-relative addressing.
    uint32_t value = 0;
    while ((uintptr_t) current_instruction < (uintptr_t) insn) {
        if (insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg) {
            value = insn_mov_imm_imm(current_instruction);
        } else if (insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg) {
            value = *(uint32_t *) (kdata + (((((uintptr_t) current_instruction - (uintptr_t) kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction)));
        } else if (insn_is_movt(current_instruction) && insn_movt_rd(current_instruction) == reg) {
            value |= insn_movt_imm(current_instruction) << 16;
        } else if (insn_is_add_reg(current_instruction) && insn_add_reg_rd(current_instruction) == reg) {
            if (insn_add_reg_rm(current_instruction) != 15 || insn_add_reg_rn(current_instruction) != reg) {
                // Can't handle this kind of operation!
                return 0;
            }

            value += ((uintptr_t) current_instruction - (uintptr_t) kdata) + 4;
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    return value;
}

// Find PC-relative references to a certain address (relative to kdata). This is basically a virtual machine that only cares about instructions used in PC-relative addressing, so no branches, etc.
static uint16_t *find_literal_ref(uint32_t region, uint8_t * kdata, size_t ksize, uint16_t * insn, uint32_t address)
{
    uint16_t *current_instruction = insn;
    uint32_t value[16];
    memset(value, 0, sizeof(value));

    while ((uintptr_t) current_instruction < (uintptr_t) (kdata + ksize)) {
        if (insn_is_mov_imm(current_instruction)) {
            value[insn_mov_imm_rd(current_instruction)] = insn_mov_imm_imm(current_instruction);
        } else if (insn_is_ldr_literal(current_instruction)) {
            uintptr_t literal_address = (uintptr_t) kdata + ((((uintptr_t) current_instruction - (uintptr_t) kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction);
            if (literal_address >= (uintptr_t) kdata && (literal_address + 4) <= ((uintptr_t) kdata + ksize)) {
                value[insn_ldr_literal_rt(current_instruction)] = *(uint32_t *) (literal_address);
            }
        } else if (insn_is_movt(current_instruction)) {
            value[insn_movt_rd(current_instruction)] |= insn_movt_imm(current_instruction) << 16;
        } else if (insn_is_add_reg(current_instruction)) {
            int reg = insn_add_reg_rd(current_instruction);
            if (insn_add_reg_rm(current_instruction) == 15 && insn_add_reg_rn(current_instruction) == reg) {
                value[reg] += ((uintptr_t) current_instruction - (uintptr_t) kdata) + 4;
                if (value[reg] == address) {
                    return current_instruction;
                }
            }
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    return NULL;
}

// This points to kernel_pmap. Use that to change the page tables if necessary.
uint32_t find_pmap_location(uint32_t region, uint8_t * kdata, size_t ksize)
{
    // Find location of the pmap_map_bd string.
    uint8_t *pmap_map_bd = memmem(kdata, ksize, "\"pmap_map_bd\"", sizeof("\"pmap_map_bd\""));
    if (!pmap_map_bd)
        return 0;

    // Find a reference to the pmap_map_bd string. That function also references kernel_pmap
    uint16_t *ptr = find_literal_ref(region, kdata, ksize, (uint16_t *) kdata, (uintptr_t) pmap_map_bd - (uintptr_t) kdata);
    if (!ptr)
        return 0;

    // Find the end of it.
    const uint8_t search_function_end[] = { 0xF0, 0xBD };
    ptr = memmem(ptr, ksize - ((uintptr_t) ptr - (uintptr_t) kdata), search_function_end, sizeof(search_function_end));
    if (!ptr)
        return 0;

    // Find the last BL before the end of it. The third argument to it should be kernel_pmap
    uint16_t *bl = find_last_insn_matching(region, kdata, ksize, ptr, insn_is_bl);
    if (!bl)
        return 0;

    // Find the last LDR R2, [R*] before it that's before any branches. If there are branches, then we have a version of the function that assumes kernel_pmap instead of being passed it.
    uint16_t *ldr_r2 = NULL;
    uint16_t *current_instruction = bl;
    while ((uintptr_t) current_instruction > (uintptr_t) kdata) {
        if (insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3)) {
            current_instruction -= 2;
        } else {
            --current_instruction;
        }

        if (insn_ldr_imm_rt(current_instruction) == 2 && insn_ldr_imm_imm(current_instruction) == 0) {
            ldr_r2 = current_instruction;
            break;
        } else if (insn_is_b_conditional(current_instruction) || insn_is_b_unconditional(current_instruction)) {
            break;
        }
    }

    // The function has a third argument, which must be kernel_pmap. Find out its address
    if (ldr_r2)
        return find_pc_rel_value(region, kdata, ksize, ldr_r2, insn_ldr_imm_rn(ldr_r2));

    // The function has no third argument, Follow the BL.
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t) bl - (uintptr_t) kdata) + 4 + imm32;
    if (target > ksize)
        return 0;

    // Find the first PC-relative reference in this function.
    int found = 0;

    int rd;
    current_instruction = (uint16_t *) (kdata + target);
    while ((uintptr_t) current_instruction < (uintptr_t) (kdata + ksize)) {
        if (insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15) {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    if (!found)
        return 0;

    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

// Function to find the syscall 0 function pointer. Used to modify the syscall table to call our own code.
uint32_t find_syscall0(uint32_t region, uint8_t * kdata, size_t ksize)
{
    // Search for the preamble to syscall 1
    const uint8_t syscall1_search[] = { 0x90, 0xB5, 0x01, 0xAF, 0x82, 0xB0, 0x09, 0x68, 0x01, 0x24, 0x00, 0x23 };
    void *ptr = memmem(kdata, ksize, syscall1_search, sizeof(syscall1_search));
    if (!ptr)
        return 0;

    // Search for a pointer to syscall 1
    uint32_t ptr_address = (uintptr_t) ptr - (uintptr_t) kdata + region;
    uint32_t function = ptr_address | 1;
    void *syscall1_entry = memmem(kdata, ksize, &function, sizeof(function));
    if (!syscall1_entry)
        return 0;

    // Calculate the address of syscall 0 from the address of the syscall 1 entry
    return (uintptr_t) syscall1_entry - (uintptr_t) kdata - 0x18;
}

// 0E E0 9F E7 FF FF FF EA C0 00 0C F1
// ldr lr, [pc, lr]
// b +0x0
// cpsid if

uint32_t find_larm_init_tramp(uint32_t region, uint8_t * kdata, size_t ksize)
{
    const uint8_t search[] = { 0x0E, 0xE0, 0x9F, 0xE7, 0xFF, 0xFF, 0xFF, 0xEA, 0xC0, 0x00, 0x0C, 0xF1 };
    void *ptr = memmem(kdata, ksize, search, sizeof(search));
    if (!ptr)
        return 0;

    return ((uintptr_t) ptr) - ((uintptr_t) kdata);
}

/* --- planetbeing patchfinder --- */

uint32_t phys_addr_remap = 0x5fe00000;

vm_address_t get_kernel_base()
{
    kern_return_t ret;
    task_t kernel_task;
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    vm_address_t addr = 0x81200000;

    ret = task_for_pid(mach_task_self(), 0, &kernel_task);
    if (ret != KERN_SUCCESS)
        return 0;

    while (1) {
        ret = vm_region_recurse_64(kernel_task, &addr, &size, &depth, (vm_region_info_t) & info, &info_count);
        if (ret != KERN_SUCCESS)
            break;
        if (size > 1024 * 1024 * 1024)
            return addr;
        addr += size;
    }

    return 0;
}

static void generate_ttb_entries(void)
{
    uint32_t vaddr, vaddr_end, paddr, i;

    paddr = PHYS_OFF;
    vaddr = SHADOWMAP_BEGIN;
    vaddr_end = SHADOWMAP_END;

    for (i = vaddr; i <= vaddr_end; i += SHADOWMAP_GRANULARITY, paddr += SHADOWMAP_GRANULARITY) {
#if SPURIOUS_DEBUG_OUTPUT
        printf("ProtoTTE: 0x%08x for VA 0x%08x -> PA 0x%08x\n", L1_PROTO_TTE(paddr), i, paddr);
#endif
        ttb_template[TTB_OFFSET(i) >> PFN_SHIFT] = L1_PROTO_TTE(paddr);
    }

    /*
     * Remap TTE for iBoot load address. 
     */
    uint32_t ttb_remap_addr_base = 0x7fe00000;
    ttb_template[TTB_OFFSET(ttb_remap_addr_base) >> PFN_SHIFT] = L1_PROTO_TTE(phys_addr_remap);
    ttb_template[TTB_OFFSET(ttb_remap_addr_base - 1048576) >> PFN_SHIFT] = L1_PROTO_TTE(phys_addr_remap - (1048576));

#if SPURIOUS_DEBUG_OUTPUT
    printf("remap -> 0x%08x => 0x%08x (TTE: 0x%08x)\n", ttb_remap_addr_base, phys_addr_remap, L1_PROTO_TTE(phys_addr_remap));

    printf("TTE offset begin for shadowmap: 0x%08x\n" "TTE offset end for shadowmap:   0x%08x\n" "TTE size:                       0x%08x\n", SHADOWMAP_BEGIN_OFF, SHADOWMAP_END_OFF, SHADOWMAP_SIZE);
#endif

    printf("New TTEs generated, base address for remap: 0x%08x, physBase: 0x%08x\n", PHYS_OFF, phys_addr_remap);
    printf("[multi_kloader] 0x%08x => 0x%08x\n", ttb_remap_addr_base - 1048576, phys_addr_remap - (1048576));
    return;
}

#define DMPSIZE     0xc00000
extern void *shellcode_begin, shellcode_end;
extern uint32_t larm_init_tramp;
extern uint32_t flush_dcache, invalidate_icache;
extern uint32_t kern_base, kern_tramp_phys;

int main(int argc, char *argv[])
{
    uint32_t chunksize = 2048;
    struct stat st;

    if (argc != 3) {
        printf("usage: %s [loadfile] [loadfile2]\n"
               "This will destroy the current running OS instance and fire up the loaded image.\n"
               "You have been warned.\n", argv[0]);
        return -1;
    }

    if (stat(argv[1], &st) == -1) {
        printf("Failed to open %s.\n", argv[1]);
        return -1;
    }

    if (stat(argv[2], &st) == -1) {
        printf("Failed to open %s.\n", argv[2]);
        return -1;
    }

    /*
     * Get physbase. 
     */
    size_t size;
    sysctlbyname("kern.version", NULL, &size, NULL, 0);
    char *osversion = malloc(size);
    if (sysctlbyname("kern.version", osversion, &size, NULL, 0) == -1) {
        printf("fail to kern.version sysctl\n");
        exit(-1);
    }
#if SPURIOUS_DEBUG_OUTPUT
    printf("%s\n", osversion);
#endif

    if (strcasestr(osversion, "s5l8930x")) {
        PHYS_OFF = S5L8930_PHYS_OFF;
        phys_addr_remap = 0x5fe00000;
    } else if (strcasestr(osversion, "s5l8920x") || strcasestr(osversion, "s5l8922x")) {
        PHYS_OFF = S5L8930_PHYS_OFF;
        phys_addr_remap = 0x4fe00000;
    } else if (strcasestr(osversion, "s5l8940x")) {
        /*
         * All others have the high ram base. 
         */
        PHYS_OFF = S5L8940_PHYS_OFF;
        phys_addr_remap = 0x9fe00000;
    } else {
        printf("Bravely assuming you're on an 8940-class device (unrecognized). You are on your own.\n");
        /*
         * All others have the high ram base. 
         */
        PHYS_OFF = S5L8940_PHYS_OFF;
        phys_addr_remap = 0x9fe00000;
    }

    /*
     * Pedanticness, though doesn't matter, after we quit the entire OS is gone lol 
     */
    free(osversion);

#if SPURIOUS_DEBUG_OUTPUT
    printf("physOff 0x%08x remap 0x%08x\n", PHYS_OFF, phys_addr_remap);
#endif

    /*
     * generate TTEs. 
     */
    generate_ttb_entries();

    /*
     * get kernel base. 
     */
    kernel_base = get_kernel_base();
    if (kernel_base == -1) {
        printf("failed to get kernel_baseel base...\n");
        return -1;
    }

    printf("Kernel base is 0x%08x.\n", kernel_base);

    /*
     * we can now find the kernel pmap. 
     */
    kern_return_t r = task_for_pid(mach_task_self(), 0, &kernel_task);
    if (r != 0) {
        printf("task_for_pid failed.\n");
        return -1;
    }

    /*
     * kill 
     */
    uint32_t addr = kernel_base + 0x1000, e = 0, sz = 0;
    uint8_t *p = malloc(DMPSIZE + 0x1000);
    pointer_t buf;

    if (!p) {
        printf("failed to malloc memory for kernel dump...\n");
        return -1;
    }
    while (addr < (kernel_base + DMPSIZE)) {
        vm_read(kernel_task, addr, chunksize, &buf, &sz);
        if (!buf || sz == 0)
            continue;
        uint8_t *z = (uint8_t *) buf;
        addr += chunksize;
        bcopy(z, p + e, chunksize);
        e += chunksize;
    }

    /*
     * kernel dumped, now find pmap. 
     */
    uint32_t kernel_pmap = kernel_base + 0x1000 + find_pmap_location(kernel_base, (uint8_t *) p, DMPSIZE);
    printf("kernel pmap is at 0x%08x.\n", kernel_pmap);

    /*
     * Read for kernel_pmap, dereference it for pmap_store. 
     */
    vm_read(kernel_task, kernel_pmap, 2048, &buf, &sz);
    vm_read(kernel_task, *(uint32_t *) (buf), 2048, &buf, &sz);

    /*
     * We now have the struct. Let's copy it out to get the TTE base (we don't really need to do this
     * as it should just remain constant. TTEs should be after ToKD.)
     */
    pmap_partial_t *part = (pmap_partial_t *) buf;
    uint32_t tte_virt = part->tte_virt;
    uint32_t tte_phys = part->tte_phys;

    printf("kernel pmap details: tte_virt: 0x%08x tte_phys: 0x%08x\n", tte_virt, tte_phys);

    /*
     * Now, we can start reading at the TTE base and start writing in the descriptors. 
     */
    uint32_t tte_off = SHADOWMAP_BEGIN_OFF;
    vm_read(kernel_task, tte_virt + tte_off, 2048, &buf, &sz);
    bcopy((char *) ttb_template_ptr + tte_off, (void *) buf, SHADOWMAP_SIZE);
    vm_write(kernel_task, tte_virt + tte_off, buf, sz);

    printf("======================================================================================\n");
    printf("!!!! Kernel TTE entries written. System stability is no longer guaranteed.\n");
    printf("!!!! Security has also been reduced by an exponential factor. You have been warned.\n");
    printf("======================================================================================\n");

    if (signal(SIGINT, SIG_IGN) != SIG_IGN)
        signal(SIGINT, SIG_IGN);

    /*
     * remap_address = 0x7ff00000 
     */
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        printf("Failed to open iBEC. Rebooting momentarily...\n");
        sleep(3);
        reboot(0);
    }

    fseek(f, 0, SEEK_END);
    int length = ftell(f);
    fseek(f, 0, SEEK_SET);
    void *vp = malloc(length);
    fread(vp, length, 1, f);
    fclose(f);
    printf("Read bootloader into buffer %p, length %d\n", vp, length);

    bcopy((void *) vp, (void *) 0x7fe00000, length);

    /*
     * Verify ARM header. 
     */
    if (*(uint32_t *) 0x7fe00000 != 0xea00000e) {
        printf("This doesn't seem like an ARM image, perhaps it failed to copy? Continuing though.\n");
    }

    printf("Image information: %s\n", (char *) 0x7fe00000 + 0x200);
    printf("Image information: %s\n", (char *) 0x7fe00000 + 0x240);
    printf("Image information: %s\n", (char *) 0x7fe00000 + 0x280);

    free(vp);

    /* 
     * Second image at 0x7fd00000.
     */
    f = fopen(argv[2], "rb");
    if (!f) {
        printf("Failed to open iBEC. Rebooting momentarily...\n");
        sleep(3);
        reboot(0);
    }

    fseek(f, 0, SEEK_END);
    length = ftell(f);
    fseek(f, 0, SEEK_SET);
    vp = malloc(length);
    fread(vp, length, 1, f);
    fclose(f);
    printf("Read bootloader into buffer %p, length %d\n", vp, length);

    bcopy((void *) vp, (void *) 0x7fd00000, length);

    /*
     * Verify ARM header. 
     */
    if (*(uint32_t *) 0x7fd00000 != 0xea00000e) {
        printf("This doesn't seem like an ARM image, perhaps it failed to copy? Continuing though.\n");
    }

    printf("Image information: %s\n", (char *) 0x7fd00000 + 0x200);
    printf("Image information: %s\n", (char *) 0x7fd00000 + 0x240);
    printf("Image information: %s\n", (char *) 0x7fd00000 + 0x280);

    free(vp);

    /*
     * iBEC copied, we need to copy over the shellcode now. 
     */
    uint32_t sysent_common = 0x1000 + find_syscall0(kernel_base + 0x1000, (uint8_t *) p, DMPSIZE) + SHADOWMAP_BEGIN;
    printf("sysent_common_base: 0x%08x\n", sysent_common);

    /*
     * fuck evasi0n7 
     */
    if (*(uint32_t *) (sysent_common) == 0) {
        printf("iOS 7 detected, adjusting base to 0x%08x = 0x%08x\n", sysent_common, *(uint32_t *) (sysent_common));
        sysent_common += 4;
        if (*(uint32_t *) (sysent_common) == 0) {
            printf("Something is severely wrong (blaming iOS 7 anyhow). Rebooting momentarily.\n");
            sleep(3);
            reboot(0);
        }
    }

    /*
     * Set offsets. 
     */
    larm_init_tramp = 0x1000 + find_larm_init_tramp(kernel_base + 0x1000, (uint8_t *) p, DMPSIZE) + SHADOWMAP_BEGIN;

    kern_base = kernel_base;
    kern_tramp_phys = phys_addr_remap;

#if 1

    printf("larm_init_tramp is at 0x%08x\n", larm_init_tramp);
    bcopy((void *) &shellcode_begin, (void *) 0x7f000c00, (uint32_t) ((uintptr_t) & shellcode_end - (uintptr_t) & shellcode_begin));
    *(uint32_t *) sysent_common = 0x7f000c01;

    printf("Running shellcode now.\n");
    syscall(0);

    printf("Syncing disks.\n");
    int diskSync;
    for (diskSync = 0; diskSync < 10; diskSync++)
        sync();
    sleep(1);

#else
    // Requires D-cache writeback.
    printf("Tramp %x COMMMAP\n", larm_init_tramp - kernel_base + SHADOWMAP_BEGIN);
    printf("%x, %x\n", *(uintptr_t *) (0x7f000000 + (larm_init_tramp - kernel_base)), *(uintptr_t *) (0x7f000000 + (larm_init_tramp - kernel_base) + 4));
    printf("%x\n", *(uint32_t *) (0x7f000000 + 0x1000));
    bcopy((void *) arm, (void *) 0x7f000000 + (larm_init_tramp - kernel_base), sizeof(arm));
    printf("%x, %x\n", *(uintptr_t *) (0x7f000000 + (larm_init_tramp - kernel_base)), *(uintptr_t *) (0x7f000000 + (larm_init_tramp - kernel_base) + 4));
    printf("%x\n", *(uint32_t *) (0x7f000000 + 0x1000));
#endif

    while (1) {
        printf("Magic happening now. (attempted!)\n");
        mach_port_t fb = IOPMFindPowerManagement(MACH_PORT_NULL);
        if (fb != MACH_PORT_NULL) {
            kern_return_t kr = IOPMSleepSystem(fb);
            if (kr) {
                err(1, "IOPMSleepSystem returned %x\n", kr);
            }
        } else {
            err(1, "failed to get PM root port\n");
        }
        sleep(3);
    }

    return 0;
}

/* how evil can you get???? */
#if INLINE_IT_ALL
/* hey, you gotta compile with -no-integrated-as */
#ifdef __arm__
__asm__("\n"
        "    .code 16\n"
        "    .thumb_func\n"
        "    .align 2\n"
        "    .data\n"
        "    .globl _shellcode_begin\n"
        "    .globl _shellcode_end\n"
        "    .globl _larm_init_tramp\n"
        "    .globl _flush_dcache\n"
        "    .globl _invalidate_icache\n"
        "    .globl _kern_tramp_phys\n"
        "    .globl _kern_base\n"
        "_shellcode_begin:\n"
        "    mrs r12, cpsr\n"
        "    cpsid   if\n"
        "    ldr r0, 0f\n"
        "    ldr r1, _kern_tramp_phys\n"
        "    ldr r2, _larm_init_tramp\n"
        "    str r0, [r2]\n"
        "    str r1, [r2, #4]\n"
        "    ldr r0, _kern_base\n"
        "    @ Clear cache to PoC\n"
        "    ldr r2, _larm_init_tramp\n"
        "    bic r2, r2, #((1 << 6) - 1)\n"
        "    mcr p15, 0, r2, c7, c14, 1\n"
        "    mov r1, #256\n"
        ".Lloop:\n"
        "    add r2, r2, #(1 << 6)\n"
        "    mcr p15, 0, r2, c7, c14, 1\n"
        "    subs    r1, r1, #1\n"
        "    bne .Lloop\n"
        "    msr cpsr_c, r12\n"
        "    movs    r0, #0\n"
        "    bx  lr\n"
        "    .align 2\n"
        "0:  .long   0xe51ff004\n"
        "_kern_tramp_phys:   .long   0x9bf00000\n"
        "_kern_base:     .long   0xdeadbeef\n"
        "_larm_init_tramp:   .long   0xdeadbeef\n"
        "_flush_dcache:      .long   0xdeadbeef\n"
        "_invalidate_icache: .long   0xdeadbeef\n"
        "_shellcode_end:\n"
        "    nop\n");
#else
#error - this is only for ARM..
#endif
#endif
