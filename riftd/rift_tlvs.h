/*
 * RIFT TLV Serializer/Deserializer
 *
 * Copyright (C) 2019 Bruno Rijsman
 *
 * This code is based on the original FRR IS-IS code, which is:
 * 
 * Copyright (C) 2015,2017 Christian Franke
 *
 * This file is part of FRR.
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
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#ifndef RIFT_TLVS_H
#define RIFT_TLVS_H

#include "openbsd-tree.h"
#include "prefix.h"
#include "riftd/dict.h"

struct rift_subtlvs;

struct rift_area_address;
struct rift_area_address {
	struct rift_area_address *next;

	uint8_t addr[20];
	uint8_t len;
};

struct rift_oldstyle_reach;
struct rift_oldstyle_reach {
	struct rift_oldstyle_reach *next;

	uint8_t id[7];
	uint8_t metric;
};

struct rift_oldstyle_ip_reach;
struct rift_oldstyle_ip_reach {
	struct rift_oldstyle_ip_reach *next;

	uint8_t metric;
	struct prefix_ipv4 prefix;
};

struct rift_lsp_entry;
struct rift_lsp_entry {
	struct rift_lsp_entry *next;

	uint16_t rem_lifetime;
	uint8_t id[8];
	uint16_t checksum;
	uint32_t seqno;

	struct rift_lsp *lsp;
};

struct rift_extended_reach;
struct rift_extended_reach {
	struct rift_extended_reach *next;

	uint8_t id[7];
	uint32_t metric;

	uint8_t *subtlvs;
	uint8_t subtlv_len;
};

struct rift_extended_ip_reach;
struct rift_extended_ip_reach {
	struct rift_extended_ip_reach *next;

	uint32_t metric;
	bool down;
	struct prefix_ipv4 prefix;

	struct rift_subtlvs *subtlvs;
};

struct rift_ipv6_reach;
struct rift_ipv6_reach {
	struct rift_ipv6_reach *next;

	uint32_t metric;
	bool down;
	bool external;

	struct prefix_ipv6 prefix;

	struct rift_subtlvs *subtlvs;
};

struct rift_protocols_supported {
	uint8_t count;
	uint8_t *protocols;
};

#define RIFT_TIER_UNDEFINED 15

struct rift_spine_leaf {
	uint8_t tier;

	bool has_tier;
	bool is_leaf;
	bool is_spine;
	bool is_backup;
};

enum rift_threeway_state {
	RIFT_THREEWAY_DOWN = 2,
	RIFT_THREEWAY_INITIALIZING = 1,
	RIFT_THREEWAY_UP = 0
};

struct rift_threeway_adj {
	enum rift_threeway_state state;
	uint32_t local_circuit_id;
	bool neighbor_set;
	uint8_t neighbor_id[6];
	uint32_t neighbor_circuit_id;
};

struct rift_item;
struct rift_item {
	struct rift_item *next;
};

struct rift_lan_neighbor;
struct rift_lan_neighbor {
	struct rift_lan_neighbor *next;

	uint8_t mac[6];
};

struct rift_ipv4_address;
struct rift_ipv4_address {
	struct rift_ipv4_address *next;

	struct in_addr addr;
};

struct rift_ipv6_address;
struct rift_ipv6_address {
	struct rift_ipv6_address *next;

	struct in6_addr addr;
};

struct rift_mt_router_info;
struct rift_mt_router_info {
	struct rift_mt_router_info *next;

	bool overload;
	bool attached;
	uint16_t mtid;
};

struct rift_auth;
struct rift_auth {
	struct rift_auth *next;

	uint8_t type;
	uint8_t length;
	uint8_t value[256];

	uint8_t plength;
	uint8_t passwd[256];

	size_t offset; /* Only valid after packing */
};

struct rift_item_list;
struct rift_item_list {
	struct rift_item *head;
	struct rift_item **tail;

	RB_ENTRY(rift_item_list) mt_tree;
	uint16_t mtid;
	unsigned int count;
};

struct rift_purge_originator {
	bool sender_set;

	uint8_t generator[6];
	uint8_t sender[6];
};

enum rift_auth_result {
	RIFT_AUTH_OK = 0,
	RIFT_AUTH_TYPE_FAILURE,
	RIFT_AUTH_FAILURE,
	RIFT_AUTH_NO_VALIDATOR,
};

RB_HEAD(rift_mt_item_list, rift_item_list);

struct rift_item_list *rift_get_mt_items(struct rift_mt_item_list *m,
					 uint16_t mtid);
struct rift_item_list *rift_lookup_mt_items(struct rift_mt_item_list *m,
					    uint16_t mtid);

struct rift_tlvs {
	struct rift_item_list rift_auth;
	struct rift_purge_originator *purge_originator;
	struct rift_item_list area_addresses;
	struct rift_item_list oldstyle_reach;
	struct rift_item_list lan_neighbor;
	struct rift_item_list lsp_entries;
	struct rift_item_list extended_reach;
	struct rift_mt_item_list mt_reach;
	struct rift_item_list oldstyle_ip_reach;
	struct rift_protocols_supported protocols_supported;
	struct rift_item_list oldstyle_ip_reach_ext;
	struct rift_item_list ipv4_address;
	struct rift_item_list ipv6_address;
	struct rift_item_list mt_router_info;
	bool mt_router_info_empty;
	struct in_addr *te_router_id;
	struct rift_item_list extended_ip_reach;
	struct rift_mt_item_list mt_ip_reach;
	char *hostname;
	struct rift_item_list ipv6_reach;
	struct rift_mt_item_list mt_ipv6_reach;
	struct rift_threeway_adj *threeway_adj;
	struct rift_spine_leaf *spine_leaf;
};

#define RIFT_PREFIX_SID_READVERTISED  0x80
#define RIFT_PREFIX_SID_NODE          0x40
#define RIFT_PREFIX_SID_NO_PHP        0x20
#define RIFT_PREFIX_SID_EXPLICIT_NULL 0x10
#define RIFT_PREFIX_SID_VALUE         0x08
#define RIFT_PREFIX_SID_LOCAL         0x04

struct rift_prefix_sid;
struct rift_prefix_sid {
	struct rift_prefix_sid *next;

	uint8_t flags;
	uint8_t algorithm;

	uint32_t value;
};

enum rift_tlv_context {
	RIFT_CONTEXT_LSP,
	RIFT_CONTEXT_SUBTLV_NE_REACH,
	RIFT_CONTEXT_SUBTLV_IP_REACH,
	RIFT_CONTEXT_SUBTLV_IPV6_REACH,
	RIFT_CONTEXT_MAX
};

struct rift_subtlvs {
	enum rift_tlv_context context;

	/* draft-baker-ipv6-rift-dst-src-routing-06 */
	struct prefix_ipv6 *source_prefix;
	/* draft-ietf-rift-segment-routing-extensions-16 */
	struct rift_item_list prefix_sids;
};

enum rift_tlv_type {
	RIFT_TLV_AREA_ADDRESSES = 1,
	RIFT_TLV_OLDSTYLE_REACH = 2,
	RIFT_TLV_LAN_NEIGHBORS = 6,
	RIFT_TLV_PADDING = 8,
	RIFT_TLV_LSP_ENTRY = 9,
	RIFT_TLV_AUTH = 10,
	RIFT_TLV_PURGE_ORIGINATOR = 13,
	RIFT_TLV_EXTENDED_REACH = 22,

	RIFT_TLV_OLDSTYLE_IP_REACH = 128,
	RIFT_TLV_PROTOCOLS_SUPPORTED = 129,
	RIFT_TLV_OLDSTYLE_IP_REACH_EXT = 130,
	RIFT_TLV_IPV4_ADDRESS = 132,
	RIFT_TLV_TE_ROUTER_ID = 134,
	RIFT_TLV_EXTENDED_IP_REACH = 135,
	RIFT_TLV_DYNAMIC_HOSTNAME = 137,
	RIFT_TLV_SPINE_LEAF_EXT = 150,
	RIFT_TLV_MT_REACH = 222,
	RIFT_TLV_MT_ROUTER_INFO = 229,
	RIFT_TLV_IPV6_ADDRESS = 232,
	RIFT_TLV_MT_IP_REACH = 235,
	RIFT_TLV_IPV6_REACH = 236,
	RIFT_TLV_MT_IPV6_REACH = 237,
	RIFT_TLV_THREE_WAY_ADJ = 240,
	RIFT_TLV_MAX = 256,

	RIFT_SUBTLV_PREFIX_SID = 3,
	RIFT_SUBTLV_IPV6_SOURCE_PREFIX = 22
};

#define IS_COMPAT_MT_TLV(tlv_type)                                             \
	((tlv_type == RIFT_TLV_MT_REACH) || (tlv_type == RIFT_TLV_MT_IP_REACH) \
	 || (tlv_type == RIFT_TLV_MT_IPV6_REACH))

struct stream;
int rift_pack_tlvs(struct rift_tlvs *tlvs, struct stream *stream,
		   size_t len_pointer, bool pad, bool is_lsp);
void rift_free_tlvs(struct rift_tlvs *tlvs);
struct rift_tlvs *rift_alloc_tlvs(void);
int rift_unpack_tlvs(size_t avail_len, struct stream *stream,
		     struct rift_tlvs **dest, const char **error_log);
const char *rift_format_tlvs(struct rift_tlvs *tlvs);
struct rift_tlvs *rift_copy_tlvs(struct rift_tlvs *tlvs);
struct list *rift_fragment_tlvs(struct rift_tlvs *tlvs, size_t size);

#define RIFT_EXTENDED_IP_REACH_DOWN 0x80
#define RIFT_EXTENDED_IP_REACH_SUBTLV 0x40

#define RIFT_IPV6_REACH_DOWN 0x80
#define RIFT_IPV6_REACH_EXTERNAL 0x40
#define RIFT_IPV6_REACH_SUBTLV 0x20

#ifndef RIFT_MT_MASK
#define RIFT_MT_MASK           0x0fff
#define RIFT_MT_OL_MASK        0x8000
#define RIFT_MT_AT_MASK        0x4000
#endif


void rift_tlvs_add_auth(struct rift_tlvs *tlvs, struct rift_passwd *passwd);
void rift_tlvs_add_area_addresses(struct rift_tlvs *tlvs,
				  struct list *addresses);
void rift_tlvs_add_lan_neighbors(struct rift_tlvs *tlvs,
				 struct list *neighbors);
void rift_tlvs_set_protocols_supported(struct rift_tlvs *tlvs,
				       struct nlpids *nlpids);
void rift_tlvs_add_mt_router_info(struct rift_tlvs *tlvs, uint16_t mtid,
				  bool overload, bool attached);
void rift_tlvs_add_ipv4_address(struct rift_tlvs *tlvs, struct in_addr *addr);
void rift_tlvs_add_ipv4_addresses(struct rift_tlvs *tlvs,
				  struct list *addresses);
void rift_tlvs_add_ipv6_addresses(struct rift_tlvs *tlvs,
				  struct list *addresses);
int rift_tlvs_auth_is_valid(struct rift_tlvs *tlvs, struct rift_passwd *passwd,
			    struct stream *stream, bool is_lsp);
bool rift_tlvs_area_addresses_match(struct rift_tlvs *tlvs,
				    struct list *addresses);
struct rift_adjacency;
void rift_tlvs_to_adj(struct rift_tlvs *tlvs, struct rift_adjacency *adj,
		      bool *changed);
bool rift_tlvs_own_snpa_found(struct rift_tlvs *tlvs, uint8_t *snpa);
void rift_tlvs_add_lsp_entry(struct rift_tlvs *tlvs, struct rift_lsp *lsp);
void rift_tlvs_add_csnp_entries(struct rift_tlvs *tlvs, uint8_t *start_id,
				uint8_t *stop_id, uint16_t num_lsps,
				dict_t *lspdb, struct rift_lsp **last_lsp);
void rift_tlvs_set_dynamic_hostname(struct rift_tlvs *tlvs,
				    const char *hostname);
void rift_tlvs_set_te_router_id(struct rift_tlvs *tlvs,
				const struct in_addr *id);
void rift_tlvs_add_oldstyle_ip_reach(struct rift_tlvs *tlvs,
				     struct prefix_ipv4 *dest, uint8_t metric);
void rift_tlvs_add_extended_ip_reach(struct rift_tlvs *tlvs,
				     struct prefix_ipv4 *dest, uint32_t metric);
void rift_tlvs_add_ipv6_reach(struct rift_tlvs *tlvs, uint16_t mtid,
			      struct prefix_ipv6 *dest, uint32_t metric);
void rift_tlvs_add_ipv6_dstsrc_reach(struct rift_tlvs *tlvs, uint16_t mtid,
				     struct prefix_ipv6 *dest,
				     struct prefix_ipv6 *src,
				     uint32_t metric);
void rift_tlvs_add_oldstyle_reach(struct rift_tlvs *tlvs, uint8_t *id,
				  uint8_t metric);
void rift_tlvs_add_extended_reach(struct rift_tlvs *tlvs, uint16_t mtid,
				  uint8_t *id, uint32_t metric,
				  uint8_t *subtlvs, uint8_t subtlv_len);

const char *rift_threeway_state_name(enum rift_threeway_state state);

void rift_tlvs_add_threeway_adj(struct rift_tlvs *tlvs,
				enum rift_threeway_state state,
				uint32_t local_circuit_id,
				const uint8_t *neighbor_id,
				uint32_t neighbor_circuit_id);

void rift_tlvs_add_spine_leaf(struct rift_tlvs *tlvs, uint8_t tier,
			      bool has_tier, bool is_leaf, bool is_spine,
			      bool is_backup);

struct rift_mt_router_info *
rift_tlvs_lookup_mt_router_info(struct rift_tlvs *tlvs, uint16_t mtid);

void rift_tlvs_set_purge_originator(struct rift_tlvs *tlvs,
				    const uint8_t *generator,
				    const uint8_t *sender);
#endif
