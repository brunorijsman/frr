/*
 * RIFT Rout(e)ing protocol - riftd.h
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

#ifndef RIFTD_H
#define RIFTD_H

#include "vty.h"

#include "riftd/rift_constants.h"
#include "riftd/rift_common.h"
#include "riftd/rift_redist.h"
#include "riftd/rift_pdu_counter.h"
#include "riftd/rift_circuit.h"
#include "rift_flags.h"
#include "dict.h"
#include "rift_memory.h"
#include "qobj.h"

static const bool fabricd = false;
#define PROTO_TYPE ZEBRA_ROUTE_RIFT
#define PROTO_NAME "rift"
#define PROTO_HELP "RIFT routing protocol\n"
#define PROTO_REDIST_STR FRR_REDIST_STR_RIFTD
#define PROTO_REDIST_HELP FRR_REDIST_HELP_STR_RIFTD
#define ROUTER_NODE RIFT_NODE
extern void rift_cli_init(void);

extern struct zebra_privs_t riftd_privs;

/* uncomment if you are a developer in bug hunt */
/* #define EXTREME_DEBUG  */
/* #define EXTREME_DICT_DEBUG */

struct fabricd;   /* TODO: Get rid of this */

struct rift {
	unsigned long process_id;
	int sysid_set;
	uint8_t sysid[RIFT_SYS_ID_LEN]; /* SystemID for this IS */
	uint32_t router_id;		/* Router ID from zebra */
	struct list *area_list;	/* list of RIFT areas */
	struct list *init_circ_list;
	struct list *nexthops;		  /* IPv4 next hops from this IS */
	struct list *nexthops6;		  /* IPv6 next hops from this IS */
	uint8_t max_area_addrs;		  /* maximumAreaAdresses */
	struct area_addr *man_area_addrs; /* manualAreaAddresses */
	uint32_t debugs;		  /* bitmap for debug */
	time_t uptime;			  /* when did we start */
	struct thread *t_dync_clean;      /* dynamic hostname cache cleanup thread */
	uint32_t circuit_ids_used[8];     /* 256 bits to track circuit ids 1 through 255 */

	struct route_table *ext_info[REDIST_PROTOCOL_COUNT];

	QOBJ_FIELDS
};

extern struct rift *rift;
DECLARE_QOBJ_TYPE(rift_area)

enum spf_tree_id {
	SPFTREE_IPV4 = 0,
	SPFTREE_IPV6,
	SPFTREE_DSTSRC,
	SPFTREE_COUNT
};

struct lsp_refresh_arg {
	struct rift_area *area;
	int level;
};

/* for yang configuration */
enum rift_metric_style {
	RIFT_NARROW_METRIC = 0,
	RIFT_WIDE_METRIC,
	RIFT_TRANSITION_METRIC,
};

struct rift_area {
	struct rift *rift;			       /* back pointer */
	dict_t *lspdb[RIFT_LEVELS];		       /* link-state dbs */
	struct rift_spftree *spftree[SPFTREE_COUNT][RIFT_LEVELS];
#define DEFAULT_LSP_MTU 1497
	unsigned int lsp_mtu;      /* Size of LSPs to generate */
	struct list *circuit_list; /* RIFT circuits */
	struct flags flags;
	struct thread *t_tick; /* LSP walker */
	struct thread *t_lsp_refresh[RIFT_LEVELS];
	struct timeval last_lsp_refresh_event[RIFT_LEVELS];
	/* t_lsp_refresh is used in two ways:
	 * a) regular refresh of LSPs
	 * b) (possibly throttled) updates to LSPs
	 *
	 * The lsp_regenerate_pending flag tracks whether the timer is active
	 * for the a) or the b) case.
	 *
	 * It is of utmost importance to clear this flag when the timer is
	 * rescheduled for normal refresh, because otherwise, updates will
	 * be delayed until the next regular refresh.
	 */
	int lsp_regenerate_pending[RIFT_LEVELS];

	struct fabricd *fabricd;

	/*
	 * Configurables
	 */
	struct rift_passwd area_passwd;
	struct rift_passwd domain_passwd;
	/* do we support dynamic hostnames?  */
	char dynhostname;
	/* do we support new style metrics?  */
	char newmetric;
	char oldmetric;
	/* identifies the routing instance   */
	char *area_tag;
	/* area addresses for this area      */
	struct list *area_addrs;
	uint16_t max_lsp_lifetime[RIFT_LEVELS];
	char is_type; /* level-1 level-1-2 or level-2-only */
	/* are we overloaded? */
	char overload_bit;
	/* L1/L2 router identifier for inter-area traffic */
	char attached_bit;
	uint16_t lsp_refresh[RIFT_LEVELS];
	/* minimum time allowed before lsp retransmission */
	uint16_t lsp_gen_interval[RIFT_LEVELS];
	/* min interval between between consequtive SPFs */
	uint16_t min_spf_interval[RIFT_LEVELS];
	/* the percentage of LSP mtu size used, before generating a new frag */
	int lsp_frag_threshold;
	uint64_t lsp_gen_count[RIFT_LEVELS];
	uint64_t lsp_purge_count[RIFT_LEVELS];
	int ip_circuits;
	/* logging adjacency changes? */
	uint8_t log_adj_changes;
	/* multi topology settings */
	struct list *mt_settings;
	int ipv6_circuits;
	bool purge_originator;
	/* Counters */
	uint32_t circuit_state_changes;
	struct rift_redist redist_settings[REDIST_PROTOCOL_COUNT]
					  [ZEBRA_ROUTE_MAX + 1][RIFT_LEVELS];
	struct route_table *ext_reach[REDIST_PROTOCOL_COUNT][RIFT_LEVELS];

	struct spf_backoff *spf_delay_ietf[RIFT_LEVELS]; /*Structure with IETF
							    SPF algo
							    parameters*/
	struct thread *spf_timer[RIFT_LEVELS];

	struct lsp_refresh_arg lsp_refresh_arg[RIFT_LEVELS];

	pdu_counter_t pdu_tx_counters;
	pdu_counter_t pdu_rx_counters;
	uint64_t lsp_rxmt_count;

	QOBJ_FIELDS
};
DECLARE_QOBJ_TYPE(rift_area)

void rift_init(void);
void rift_new(unsigned long);
struct rift_area *rift_area_create(const char *);
struct rift_area *rift_area_lookup(const char *);
int rift_area_get(struct vty *vty, const char *area_tag);
int rift_area_destroy(const char *area_tag);
void print_debug(struct vty *, int, int);
struct rift_lsp *lsp_for_arg(const char *argv, dict_t *lspdb);

void rift_area_invalidate_routes(struct rift_area *area, int levels);
void rift_area_verify_routes(struct rift_area *area);

void rift_area_overload_bit_set(struct rift_area *area, bool overload_bit);
void rift_area_attached_bit_set(struct rift_area *area, bool attached_bit);
void rift_area_dynhostname_set(struct rift_area *area, bool dynhostname);
void rift_area_metricstyle_set(struct rift_area *area, bool old_metric,
			       bool new_metric);
void rift_area_lsp_mtu_set(struct rift_area *area, unsigned int lsp_mtu);
void rift_area_is_type_set(struct rift_area *area, int is_type);
void rift_area_max_lsp_lifetime_set(struct rift_area *area, int level,
				    uint16_t max_lsp_lifetime);
void rift_area_lsp_refresh_set(struct rift_area *area, int level,
			       uint16_t lsp_refresh);
/* IS_LEVEL_1 sets area_passwd, IS_LEVEL_2 domain_passwd */
int rift_area_passwd_unset(struct rift_area *area, int level);
int rift_area_passwd_cleartext_set(struct rift_area *area, int level,
				   const char *passwd, uint8_t snp_auth);
int rift_area_passwd_hmac_md5_set(struct rift_area *area, int level,
				  const char *passwd, uint8_t snp_auth);

extern const struct frr_yang_module_info frr_riftd_info;
extern void rift_northbound_init(void);

/* YANG northbound notifications */
extern void rift_notif_db_overload(const struct rift_area *area, bool overload);
extern void rift_notif_lsp_too_large(const struct rift_circuit *circuit,
				     uint32_t pdu_size, const char *lsp_id);
extern void rift_notif_if_state_change(const struct rift_circuit *circuit,
				       bool down);
extern void rift_notif_corrupted_lsp(const struct rift_area *area,
				     const char *lsp_id); /* currently unused */
extern void rift_notif_lsp_exceed_max(const struct rift_area *area,
				      const char *lsp_id);
extern void
rift_notif_max_area_addr_mismatch(const struct rift_circuit *circuit,
				  uint8_t max_area_addrs, const char *raw_pdu);
extern void
rift_notif_authentication_type_failure(const struct rift_circuit *circuit,
				       const char *raw_pdu);
extern void
rift_notif_authentication_failure(const struct rift_circuit *circuit,
				  const char *raw_pdu);
extern void rift_notif_adj_state_change(const struct rift_adjacency *adj,
					int new_state, const char *reason);
extern void rift_notif_reject_adjacency(const struct rift_circuit *circuit,
					const char *reason,
					const char *raw_pdu);
extern void rift_notif_area_mismatch(const struct rift_circuit *circuit,
				     const char *raw_pdu);
extern void rift_notif_lsp_received(const struct rift_circuit *circuit,
				    const char *lsp_id, uint32_t seqno,
				    uint32_t timestamp, const char *sys_id);
extern void rift_notif_lsp_gen(const struct rift_area *area, const char *lsp_id,
			       uint32_t seqno, uint32_t timestamp);
extern void rift_notif_id_len_mismatch(const struct rift_circuit *circuit,
				       uint8_t rcv_id_len, const char *raw_pdu);
extern void rift_notif_version_skew(const struct rift_circuit *circuit,
				    uint8_t version, const char *raw_pdu);
extern void rift_notif_lsp_error(const struct rift_circuit *circuit,
				 const char *lsp_id, const char *raw_pdu,
				 uint32_t offset, uint8_t tlv_type);
extern void rift_notif_seqno_skipped(const struct rift_circuit *circuit,
				     const char *lsp_id);
extern void rift_notif_own_lsp_purge(const struct rift_circuit *circuit,
				     const char *lsp_id);

/* Master of threads. */
extern struct thread_master *master;

#define DEBUG_ADJ_PACKETS                (1<<0)
#define DEBUG_SNP_PACKETS                (1<<1)
#define DEBUG_UPDATE_PACKETS             (1<<2)
#define DEBUG_SPF_EVENTS                 (1<<3)
#define DEBUG_RTE_EVENTS                 (1<<4)
#define DEBUG_EVENTS                     (1<<5)
#define DEBUG_PACKET_DUMP                (1<<6)
#define DEBUG_LSP_GEN                    (1<<7)
#define DEBUG_LSP_SCHED                  (1<<8)
#define DEBUG_FLOODING                   (1<<9)
#define DEBUG_BFD                        (1<<10)
#define DEBUG_TX_QUEUE                   (1<<11)

#define lsp_debug(...)                                                         \
	do {                                                                   \
		if (rift->debugs & DEBUG_LSP_GEN)                              \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)

#define sched_debug(...)                                                       \
	do {                                                                   \
		if (rift->debugs & DEBUG_LSP_SCHED)                            \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)

#define DEBUG_TE                         DEBUG_LSP_GEN

#define IS_DEBUG_RIFT(x)                 (rift->debugs & x)

#endif /* RIFTD_H */
