/*
 * RIFT Rout(e)ing protocol - rift_redist.h
 *
 * Copyright (C) 2013-2015 Christian Franke <chris@opensourcerouting.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
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

#ifndef RIFT_REDIST_H
#define RIFT_REDIST_H

#define REDIST_PROTOCOL_COUNT 2

#define DEFAULT_ROUTE ZEBRA_ROUTE_MAX
#define DEFAULT_ORIGINATE 1
#define DEFAULT_ORIGINATE_ALWAYS 2

struct rift_ext_info {
	int origin;
	uint32_t metric;
	uint8_t distance;
};

struct rift_redist {
	int redist;
	uint32_t metric;
	char *map_name;
	struct route_map *map;
};

struct rift_area;
struct prefix;
struct prefix_ipv6;
struct vty;

struct route_table *get_ext_reach(struct rift_area *area, int family,
				  int level);
void rift_redist_add(int type, struct prefix *p, struct prefix_ipv6 *src_p,
		     uint8_t distance, uint32_t metric);
void rift_redist_delete(int type, struct prefix *p, struct prefix_ipv6 *src_p);
int rift_redist_config_write(struct vty *vty, struct rift_area *area,
			     int family);
void rift_redist_init(void);
void rift_redist_area_finish(struct rift_area *area);

void rift_redist_set(struct rift_area *area, int level, int family, int type,
		     uint32_t metric, const char *routemap, int originate_type);
void rift_redist_unset(struct rift_area *area, int level, int family, int type);

#endif
