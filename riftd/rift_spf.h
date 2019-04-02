/*
 * RIFT Rout(e)ing protocol - rift_spf.h
 *                             RIFT Shortest Path First algorithm
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

#ifndef _ZEBRA_RIFT_SPF_H
#define _ZEBRA_RIFT_SPF_H

struct rift_spftree;

struct rift_spftree *rift_spftree_new(struct rift_area *area);
void rift_spf_invalidate_routes(struct rift_spftree *tree);
void rift_spf_verify_routes(struct rift_area *area,
			    struct rift_spftree **trees);
void rift_spftree_del(struct rift_spftree *spftree);
void spftree_area_init(struct rift_area *area);
void spftree_area_del(struct rift_area *area);
void spftree_area_adj_del(struct rift_area *area, struct rift_adjacency *adj);
#define rift_spf_schedule(area, level) \
	_rift_spf_schedule((area), (level), __func__, \
			   __FILE__, __LINE__)
int _rift_spf_schedule(struct rift_area *area, int level,
		       const char *func, const char *file, int line);
void rift_spf_cmds_init(void);
void rift_spf_print(struct rift_spftree *spftree, struct vty *vty);
struct rift_spftree *rift_run_hopcount_spf(struct rift_area *area,
					   uint8_t *sysid,
					   struct rift_spftree *spftree);
#endif /* _ZEBRA_RIFT_SPF_H */
