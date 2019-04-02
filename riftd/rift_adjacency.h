/*
 * RIFT Rout(e)ing protocol - rift_adjacency.h
 *                             RIFT adjacency handling
 *
 * Copyright (C) 2019        Bruno Rijsman
 *
 * This code is based on the original FRR IS-IS code, which is:
 * 
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
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

#ifndef _ZEBRA_RIFT_ADJACENCY_H
#define _ZEBRA_RIFT_ADJACENCY_H

#include "riftd/rift_tlvs.h"

enum rift_adj_usage {
	RIFT_ADJ_NONE,
	RIFT_ADJ_LEVEL1,
	RIFT_ADJ_LEVEL2,
	RIFT_ADJ_LEVEL1AND2
};

enum rift_system_type {
	RIFT_SYSTYPE_UNKNOWN,
	RIFT_SYSTYPE_ES,
	RIFT_SYSTYPE_IS,
	RIFT_SYSTYPE_L1_IS,
	RIFT_SYSTYPE_L2_IS
};

enum rift_adj_state {
	RIFT_ADJ_UNKNOWN,
	RIFT_ADJ_INITIALIZING,
	RIFT_ADJ_UP,
	RIFT_ADJ_DOWN
};

/*
 * we use the following codes to give an indication _why_
 * a specific adjacency is up or down
 */
enum rift_adj_updown_reason {
	RIFT_ADJ_REASON_SEENSELF,
	RIFT_ADJ_REASON_AREA_MISMATCH,
	RIFT_ADJ_REASON_HOLDTIMER_EXPIRED,
	RIFT_ADJ_REASON_AUTH_FAILED,
	RIFT_ADJ_REASON_CHECKSUM_FAILED
};

#define DIS_RECORDS 8	/* keep the last 8 DIS state changes on record */

struct rift_dis_record {
	int dis;		/* is our neighbor the DIS ? */
	time_t last_dis_change; /* timestamp for last dis change */
};

struct bfd_session;

struct rift_adjacency {
	uint8_t snpa[ETH_ALEN];		    /* NeighbourSNPAAddress */
	uint8_t sysid[RIFT_SYS_ID_LEN];     /* neighbourSystemIdentifier */
	uint8_t lanid[RIFT_SYS_ID_LEN + 1]; /* LAN id on bcast circuits */
	int dischanges[RIFT_LEVELS];       /* how many DIS changes ? */
	/* an array of N levels for M records */
	struct rift_dis_record dis_record[DIS_RECORDS * RIFT_LEVELS];
	enum rift_adj_state adj_state;    /* adjacencyState */
	enum rift_adj_usage adj_usage;    /* adjacencyUsage */
	struct area_addr *area_addresses; /* areaAdressesOfNeighbour */
	unsigned int area_address_count;
	struct nlpids nlpids; /* protocols spoken ... */
	struct in_addr *ipv4_addresses;
	unsigned int ipv4_address_count;
	struct in_addr router_address;
	struct in6_addr *ipv6_addresses;
	unsigned int ipv6_address_count;
	struct in6_addr router_address6;
	uint8_t prio[RIFT_LEVELS];      /* priorityOfNeighbour for DIS */
	int circuit_t;			/* from hello PDU hdr */
	int level;			/* level (1 or 2) */
	enum rift_system_type sys_type; /* neighbourSystemType */
	uint16_t hold_time;		/* entryRemainingTime */
	uint32_t last_upd;
	uint32_t last_flap; /* last time the adj flapped */
	enum rift_threeway_state threeway_state;
	uint32_t ext_circuit_id;
	int flaps;		      /* number of adjacency flaps  */
	struct thread *t_expire;      /* expire after hold_time  */
	struct rift_circuit *circuit; /* back pointer */
	uint16_t *mt_set;      /* Topologies this adjacency is valid for */
	unsigned int mt_count; /* Number of entries in mt_set */
	struct bfd_session *bfd_session;
};

struct rift_threeway_adj;

struct rift_adjacency *rift_adj_lookup(const uint8_t *sysid,
				       struct list *adjdb);
struct rift_adjacency *rift_adj_lookup_snpa(const uint8_t *ssnpa,
					    struct list *adjdb);
struct rift_adjacency *rift_new_adj(const uint8_t *id, const uint8_t *snpa,
				    int level, struct rift_circuit *circuit);
void rift_delete_adj(void *adj);
void rift_adj_process_threeway(struct rift_adjacency *adj,
			       struct rift_threeway_adj *tw_adj,
			       enum rift_adj_usage adj_usage);
DECLARE_HOOK(rift_adj_state_change_hook, (struct rift_adjacency *adj), (adj))
void rift_adj_state_change(struct rift_adjacency *adj,
			   enum rift_adj_state state, const char *reason);
void rift_adj_print(struct rift_adjacency *adj);
int rift_adj_expire(struct thread *thread);
void rift_adj_print_vty(struct rift_adjacency *adj, struct vty *vty,
			char detail);
void rift_adj_build_neigh_list(struct list *adjdb, struct list *list);
void rift_adj_build_up_list(struct list *adjdb, struct list *list);
int rift_adj_usage2levels(enum rift_adj_usage usage);

#endif /* RIFT_ADJACENCY_H */
