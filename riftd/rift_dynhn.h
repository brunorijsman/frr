/*
 * RIFT Rout(e)ing protocol - rift_dynhn.h
 *                             Dynamic hostname cache
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
#ifndef _ZEBRA_RIFT_DYNHN_H
#define _ZEBRA_RIFT_DYNHN_H

struct rift_dynhn {
	uint8_t id[RIFT_SYS_ID_LEN];
	char hostname[256];
	time_t refresh;
	int level;
};

void dyn_cache_init(void);
void rift_dynhn_insert(const uint8_t *id, const char *hostname, int level);
void rift_dynhn_remove(const uint8_t *id);
struct rift_dynhn *dynhn_find_by_id(const uint8_t *id);
struct rift_dynhn *dynhn_find_by_name(const char *hostname);
void dynhn_print_all(struct vty *vty);

#endif /* _ZEBRA_RIFT_DYNHN_H */
