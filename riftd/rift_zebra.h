/*
 * RIFT Rout(e)ing protocol - rift_zebra.h
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
#ifndef _ZEBRA_RIFT_ZEBRA_H
#define _ZEBRA_RIFT_ZEBRA_H

extern struct zclient *zclient;

void rift_zebra_init(struct thread_master *);
void rift_zebra_stop(void);

struct rift_route_info;

void rift_zebra_route_update(struct prefix *prefix,
			     struct prefix_ipv6 *src_p,
			     struct rift_route_info *route_info);
int rift_distribute_list_update(int routetype);
void rift_zebra_redistribute_set(afi_t afi, int type);
void rift_zebra_redistribute_unset(afi_t afi, int type);

#endif /* _ZEBRA_RIFT_ZEBRA_H */
