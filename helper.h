/*
 * Misc helpers.
 */

#ifndef _HELPER_H_
#define _HELPER_H_

#define add_ptr2(x, y) ((uintptr_t)((uintptr_t)x + (uintptr_t)y))
#define add_ptr3(x, y, z) ((uintptr_t)((uintptr_t)x + (uintptr_t)y + (uintptr_t)z))
#define align_down(p, s) ((uintptr_t)(p)&~(s-1))
#define align_up(p, s) align_down((uintptr_t)(p)+s-1, s)

#endif
