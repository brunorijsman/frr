/*
 * RIFT Rout(e)ing protocol - rift_flags.h
 *                             Routines for manipulation of SSN and SRM flags
 *
 * Copyright (C) 2019        Bruno Rijsman
 *
 * This code is based on the original FRR IS-IS code, which is:
 * 
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_RIFT_FLAGS_H
#define _ZEBRA_RIFT_FLAGS_H

/* The grand plan is to support 1024 circuits so we have 32*32 bit flags
 * the support will be achived using the newest drafts */
#define RIFT_MAX_CIRCUITS 32 /* = 1024 */

/*
 * Flags structure for SSN and SRM flags
 */
struct flags {
	int maxindex;
	struct list *free_idcs;
};

void flags_initialize(struct flags *flags);
long int flags_get_index(struct flags *flags);
void flags_free_index(struct flags *flags, long int index);
int flags_any_set(uint32_t *flags);

#define _RIFT_SET_FLAG(F, C)                                                   \
	{                                                                      \
		F[(C) >> 5] |= (1 << ((C)&0x1F));                              \
	}
#define RIFT_SET_FLAG(F, C) _RIFT_SET_FLAG(F, C->idx)

#define _RIFT_CLEAR_FLAG(F, C)                                                 \
	{                                                                      \
		F[(C) >> 5] &= ~(1 << ((C)&0x1F));                             \
	}
#define RIFT_CLEAR_FLAG(F, C) _RIFT_CLEAR_FLAG(F, C->idx)

#define _RIFT_CHECK_FLAG(F, C)  (F[(C)>>5] & (1<<((C) & 0x1F)))
#define RIFT_CHECK_FLAG(F, C) _RIFT_CHECK_FLAG(F, C->idx)

/* sets all u_32int_t flags to 1 */
#define RIFT_FLAGS_SET_ALL(FLAGS)                                              \
	{                                                                      \
		memset(FLAGS, 0xFF, RIFT_MAX_CIRCUITS * 4);                    \
	}

#define RIFT_FLAGS_CLEAR_ALL(FLAGS)                                            \
	{                                                                      \
		memset(FLAGS, 0x00, RIFT_MAX_CIRCUITS * 4);                    \
	}

#endif /* _ZEBRA_RIFT_FLAGS_H */
