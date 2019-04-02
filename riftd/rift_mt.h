/*
 * RIFT Rout(e)ing protocol - Multi Topology Support
 *
 * Copyright (C) 2017 Christian Franke
 *
 * This file is part of FreeRangeRouting (FRR)
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef RIFT_MT_H
#define RIFT_MT_H

#define RIFT_MT_MASK           0x0fff
#define RIFT_MT_OL_MASK        0x8000
#define RIFT_MT_AT_MASK        0x4000

#define RIFT_MT_IPV4_UNICAST   0
#define RIFT_MT_IPV4_MGMT      1
#define RIFT_MT_IPV6_UNICAST   2
#define RIFT_MT_IPV4_MULTICAST 3
#define RIFT_MT_IPV6_MULTICAST 4
#define RIFT_MT_IPV6_MGMT      5
#define RIFT_MT_IPV6_DSTSRC    3996 /* FIXME: IANA */

#define RIFT_MT_NAMES                                                          \
	"<ipv4-unicast"                                                        \
	"|ipv4-mgmt"                                                           \
	"|ipv6-unicast"                                                        \
	"|ipv4-multicast"                                                      \
	"|ipv6-multicast"                                                      \
	"|ipv6-mgmt"                                                           \
	"|ipv6-dstsrc"                                                         \
	">"

#define RIFT_MT_DESCRIPTIONS                                                   \
	"IPv4 unicast topology\n"                                              \
	"IPv4 management topology\n"                                           \
	"IPv6 unicast topology\n"                                              \
	"IPv4 multicast topology\n"                                            \
	"IPv6 multicast topology\n"                                            \
	"IPv6 management topology\n"                                           \
	"IPv6 dst-src topology\n"                                              \
	""

#define RIFT_MT_INFO_FIELDS uint16_t mtid;

struct list;

struct rift_area_mt_setting {
	RIFT_MT_INFO_FIELDS
	bool enabled;
	bool overload;
};

struct rift_circuit_mt_setting {
	RIFT_MT_INFO_FIELDS
	bool enabled;
};

const char *rift_mtid2str(uint16_t mtid);
uint16_t rift_str2mtid(const char *name);

struct rift_adjacency;
struct rift_area;
struct rift_circuit;
struct tlvs;
struct te_is_neigh;
struct rift_tlvs;

bool rift_area_ipv6_dstsrc_enabled(struct rift_area *area);

uint16_t rift_area_ipv6_topology(struct rift_area *area);

struct rift_area_mt_setting *area_lookup_mt_setting(struct rift_area *area,
						    uint16_t mtid);
struct rift_area_mt_setting *area_new_mt_setting(struct rift_area *area,
						 uint16_t mtid);
void area_add_mt_setting(struct rift_area *area,
			 struct rift_area_mt_setting *setting);

void area_mt_init(struct rift_area *area);
void area_mt_finish(struct rift_area *area);
struct rift_area_mt_setting *area_get_mt_setting(struct rift_area *area,
						 uint16_t mtid);
int area_write_mt_settings(struct rift_area *area, struct vty *vty);
bool area_is_mt(struct rift_area *area);
struct rift_area_mt_setting **area_mt_settings(struct rift_area *area,
					       unsigned int *mt_count);

struct rift_circuit_mt_setting *
circuit_lookup_mt_setting(struct rift_circuit *circuit, uint16_t mtid);
struct rift_circuit_mt_setting *
circuit_new_mt_setting(struct rift_circuit *circuit, uint16_t mtid);
void circuit_add_mt_setting(struct rift_circuit *circuit,
			    struct rift_circuit_mt_setting *setting);
void circuit_mt_init(struct rift_circuit *circuit);
void circuit_mt_finish(struct rift_circuit *circuit);
struct rift_circuit_mt_setting *
circuit_get_mt_setting(struct rift_circuit *circuit, uint16_t mtid);
struct rift_circuit_mt_setting **
circuit_mt_settings(struct rift_circuit *circuit, unsigned int *mt_count);
bool tlvs_to_adj_mt_set(struct rift_tlvs *tlvs, bool v4_usable, bool v6_usable,
			struct rift_adjacency *adj);
bool adj_has_mt(struct rift_adjacency *adj, uint16_t mtid);
void adj_mt_finish(struct rift_adjacency *adj);
void tlvs_add_mt_bcast(struct rift_tlvs *tlvs, struct rift_circuit *circuit,
		       int level, uint8_t *id, uint32_t metric,
		       uint8_t *subtlvs, uint8_t subtlv_len);
void tlvs_add_mt_p2p(struct rift_tlvs *tlvs, struct rift_circuit *circuit,
		     uint8_t *id, uint32_t metric, uint8_t *subtlvs,
		     uint8_t subtlv_len);
void mt_init(void);
#endif
