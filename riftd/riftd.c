/*
 * RIFT Rout(e)ing protocol - riftd.c
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

#include <zebra.h>

#include "thread.h"
#include "vty.h"
#include "command.h"
#include "log.h"
#include "memory.h"
#include "time.h"
#include "linklist.h"
#include "if.h"
#include "hash.h"
#include "stream.h"
#include "prefix.h"
#include "table.h"
#include "qobj.h"
#include "spf_backoff.h"
#include "lib/northbound_cli.h"

#include "riftd/dict.h"
#include "riftd/rift_constants.h"
#include "riftd/rift_common.h"
#include "riftd/rift_flags.h"
#include "riftd/rift_circuit.h"
#include "riftd/rift_csm.h"
#include "riftd/riftd.h"
#include "riftd/rift_dynhn.h"
#include "riftd/rift_adjacency.h"
#include "riftd/rift_pdu.h"
#include "riftd/rift_misc.h"
#include "riftd/rift_constants.h"
#include "riftd/rift_lsp.h"
#include "riftd/rift_spf.h"
#include "riftd/rift_route.h"
#include "riftd/rift_zebra.h"
#include "riftd/rift_events.h"
#include "riftd/rift_te.h"
#include "riftd/rift_mt.h"

struct rift *rift = NULL;

DEFINE_QOBJ_TYPE(rift)
DEFINE_QOBJ_TYPE(rift_area)

/*
 * Prototypes.
 */
int rift_area_get(struct vty *, const char *);
int area_net_title(struct vty *, const char *);
int area_clear_net_title(struct vty *, const char *);
int show_rift_interface_common(struct vty *, const char *ifname, char);
int show_rift_neighbor_common(struct vty *, const char *id, char);
int clear_rift_neighbor_common(struct vty *, const char *id);
int rift_config_write(struct vty *);


void rift_new(unsigned long process_id)
{
	rift = XCALLOC(MTYPE_RIFT, sizeof(struct rift));
	/*
	 * Default values
	 */
	rift->max_area_addrs = 3;
	rift->process_id = process_id;
	rift->router_id = 0;
	rift->area_list = list_new();
	rift->init_circ_list = list_new();
	rift->uptime = time(NULL);
	rift->nexthops = list_new();
	rift->nexthops6 = list_new();
	dyn_cache_init();
	/*
	 * uncomment the next line for full debugs
	 */
	/* rift->debugs = 0xFFFF; */
	riftMplsTE.status = disable; /* Only support TE metric */

	QOBJ_REG(rift, rift);
}

struct rift_area *rift_area_create(const char *area_tag)
{
	struct rift_area *area;

	area = XCALLOC(MTYPE_RIFT_AREA, sizeof(struct rift_area));

	/*
	 * Fabricd runs only as level-2.
	 * For RIFT, the first instance is level-1-2 rest are level-1,
	 * unless otherwise configured
	 */
	if (fabricd) {
		area->is_type = IS_LEVEL_2;
	} else if (listcount(rift->area_list) == 0)
		area->is_type = IS_LEVEL_1_AND_2;
	else
		area->is_type = yang_get_default_enum(
			"/frr-riftd:rift/instance/is-type");

	/*
	 * intialize the databases
	 */
	if (area->is_type & IS_LEVEL_1) {
		area->lspdb[0] = lsp_db_init();
	}
	if (area->is_type & IS_LEVEL_2) {
		area->lspdb[1] = lsp_db_init();
	}

	spftree_area_init(area);

	area->circuit_list = list_new();
	area->area_addrs = list_new();
	thread_add_timer(master, lsp_tick, area, 1, &area->t_tick);
	flags_initialize(&area->flags);

	/*
	 * Default values
	 */
	enum rift_metric_style default_style;

	area->max_lsp_lifetime[0] = yang_get_default_uint16(
		"/frr-riftd:rift/instance/lsp/maximum-lifetime/level-1");
	area->max_lsp_lifetime[1] = yang_get_default_uint16(
		"/frr-riftd:rift/instance/lsp/maximum-lifetime/level-2");
	area->lsp_refresh[0] = yang_get_default_uint16(
		"/frr-riftd:rift/instance/lsp/refresh-interval/level-1");
	area->lsp_refresh[1] = yang_get_default_uint16(
		"/frr-riftd:rift/instance/lsp/refresh-interval/level-2");
	area->lsp_gen_interval[0] = yang_get_default_uint16(
		"/frr-riftd:rift/instance/lsp/generation-interval/level-1");
	area->lsp_gen_interval[1] = yang_get_default_uint16(
		"/frr-riftd:rift/instance/lsp/generation-interval/level-2");
	area->min_spf_interval[0] = yang_get_default_uint16(
		"/frr-riftd:rift/instance/spf/minimum-interval/level-1");
	area->min_spf_interval[1] = yang_get_default_uint16(
		"/frr-riftd:rift/instance/spf/minimum-interval/level-1");
	area->dynhostname = yang_get_default_bool(
		"/frr-riftd:rift/instance/dynamic-hostname");
	default_style =
		yang_get_default_enum("/frr-riftd:rift/instance/metric-style");
	area->oldmetric = default_style == RIFT_WIDE_METRIC ? 0 : 1;
	area->newmetric = default_style == RIFT_NARROW_METRIC ? 0 : 1;
	area->lsp_frag_threshold = 90; /* not currently configurable */
	area->lsp_mtu =
		yang_get_default_uint16("/frr-riftd:rift/instance/lsp/mtu");

	area_mt_init(area);

	area->area_tag = strdup(area_tag);
	listnode_add(rift->area_list, area);
	area->rift = rift;

	/* TODO
	if (f...abricd)
		area->fabricd = f...abricd_new(area);
	*/

	area->lsp_refresh_arg[0].area = area;
	area->lsp_refresh_arg[0].level = IS_LEVEL_1;
	area->lsp_refresh_arg[1].area = area;
	area->lsp_refresh_arg[1].level = IS_LEVEL_2;


	QOBJ_REG(area, rift_area);

	return area;
}

struct rift_area *rift_area_lookup(const char *area_tag)
{
	struct rift_area *area;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(rift->area_list, node, area))
		if ((area->area_tag == NULL && area_tag == NULL)
		    || (area->area_tag && area_tag
			&& strcmp(area->area_tag, area_tag) == 0))
			return area;

	return NULL;
}

int rift_area_get(struct vty *vty, const char *area_tag)
{
	struct rift_area *area;

	area = rift_area_lookup(area_tag);

	if (area) {
		VTY_PUSH_CONTEXT(ROUTER_NODE, area);
		return CMD_SUCCESS;
	}

	area = rift_area_create(area_tag);

	if (rift->debugs & DEBUG_EVENTS)
		zlog_debug("New RIFT area instance %s", area->area_tag);

	VTY_PUSH_CONTEXT(ROUTER_NODE, area);

	return CMD_SUCCESS;
}

int rift_area_destroy(const char *area_tag)
{
	struct rift_area *area;
	struct listnode *node, *nnode;
	struct rift_circuit *circuit;
	struct area_addr *addr;

	area = rift_area_lookup(area_tag);

	if (area == NULL) {
		zlog_warn("%s: could not find area with area-tag %s",
				__func__, area_tag);
		return CMD_ERR_NO_MATCH;
	}

	QOBJ_UNREG(area);

	/* TODO
	if (f...abricd)
		f...abricd_finish(area->fabricd);
	*/

	if (area->circuit_list) {
		for (ALL_LIST_ELEMENTS(area->circuit_list, node, nnode,
				       circuit)) {
			circuit->ip_router = 0;
			circuit->ipv6_router = 0;
			rift_csm_state_change(RIFT_DISABLE, circuit, area);
		}
		list_delete(&area->circuit_list);
	}

	if (area->lspdb[0] != NULL) {
		lsp_db_destroy(area->lspdb[0]);
		area->lspdb[0] = NULL;
	}
	if (area->lspdb[1] != NULL) {
		lsp_db_destroy(area->lspdb[1]);
		area->lspdb[1] = NULL;
	}

	/* invalidate and verify to delete all routes from zebra */
	rift_area_invalidate_routes(area, RIFT_LEVEL1 & RIFT_LEVEL2);
	rift_area_verify_routes(area);

	spftree_area_del(area);

	THREAD_TIMER_OFF(area->spf_timer[0]);
	THREAD_TIMER_OFF(area->spf_timer[1]);

	spf_backoff_free(area->spf_delay_ietf[0]);
	spf_backoff_free(area->spf_delay_ietf[1]);

	rift_redist_area_finish(area);

	for (ALL_LIST_ELEMENTS(area->area_addrs, node, nnode, addr)) {
		list_delete_node(area->area_addrs, node);
		XFREE(MTYPE_RIFT_AREA_ADDR, addr);
	}
	area->area_addrs = NULL;

	THREAD_TIMER_OFF(area->t_tick);
	THREAD_TIMER_OFF(area->t_lsp_refresh[0]);
	THREAD_TIMER_OFF(area->t_lsp_refresh[1]);

	thread_cancel_event(master, area);

	listnode_delete(rift->area_list, area);

	free(area->area_tag);

	area_mt_finish(area);

	XFREE(MTYPE_RIFT_AREA, area);

	if (listcount(rift->area_list) == 0) {
		memset(rift->sysid, 0, RIFT_SYS_ID_LEN);
		rift->sysid_set = 0;
	}

	return CMD_SUCCESS;
}

int area_net_title(struct vty *vty, const char *net_title)
{
	VTY_DECLVAR_CONTEXT(rift_area, area);
	struct area_addr *addr;
	struct area_addr *addrp;
	struct listnode *node;

	uint8_t buff[255];

	/* We check that we are not over the maximal number of addresses */
	if (listcount(area->area_addrs) >= rift->max_area_addrs) {
		vty_out(vty,
			"Maximum of area addresses (%d) already reached \n",
			rift->max_area_addrs);
		return CMD_ERR_NOTHING_TODO;
	}

	addr = XMALLOC(MTYPE_RIFT_AREA_ADDR, sizeof(struct area_addr));
	addr->addr_len = dotformat2buff(buff, net_title);
	memcpy(addr->area_addr, buff, addr->addr_len);
#ifdef EXTREME_DEBUG
	zlog_debug("added area address %s for area %s (address length %d)",
		   net_title, area->area_tag, addr->addr_len);
#endif /* EXTREME_DEBUG */
	if (addr->addr_len < 8 || addr->addr_len > 20) {
		vty_out(vty,
			"area address must be at least 8..20 octets long (%d)\n",
			addr->addr_len);
		XFREE(MTYPE_RIFT_AREA_ADDR, addr);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (addr->area_addr[addr->addr_len - 1] != 0) {
		vty_out(vty,
			"nsel byte (last byte) in area address must be 0\n");
		XFREE(MTYPE_RIFT_AREA_ADDR, addr);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (rift->sysid_set == 0) {
		/*
		 * First area address - get the SystemID for this router
		 */
		memcpy(rift->sysid, GETSYSID(addr), RIFT_SYS_ID_LEN);
		rift->sysid_set = 1;
		if (rift->debugs & DEBUG_EVENTS)
			zlog_debug("Router has SystemID %s",
				   sysid_print(rift->sysid));
	} else {
		/*
		 * Check that the SystemID portions match
		 */
		if (memcmp(rift->sysid, GETSYSID(addr), RIFT_SYS_ID_LEN)) {
			vty_out(vty,
				"System ID must not change when defining additional area addresses\n");
			XFREE(MTYPE_RIFT_AREA_ADDR, addr);
			return CMD_WARNING_CONFIG_FAILED;
		}

		/* now we see that we don't already have this address */
		for (ALL_LIST_ELEMENTS_RO(area->area_addrs, node, addrp)) {
			if ((addrp->addr_len + RIFT_SYS_ID_LEN + RIFT_NSEL_LEN)
			    != (addr->addr_len))
				continue;
			if (!memcmp(addrp->area_addr, addr->area_addr,
				    addr->addr_len)) {
				XFREE(MTYPE_RIFT_AREA_ADDR, addr);
				return CMD_SUCCESS; /* silent fail */
			}
		}
	}

	/*
	 * Forget the systemID part of the address
	 */
	addr->addr_len -= (RIFT_SYS_ID_LEN + RIFT_NSEL_LEN);
	listnode_add(area->area_addrs, addr);

	/* only now we can safely generate our LSPs for this area */
	if (listcount(area->area_addrs) > 0) {
		if (area->is_type & IS_LEVEL_1)
			lsp_generate(area, IS_LEVEL_1);
		if (area->is_type & IS_LEVEL_2)
			lsp_generate(area, IS_LEVEL_2);
	}

	return CMD_SUCCESS;
}

int area_clear_net_title(struct vty *vty, const char *net_title)
{
	VTY_DECLVAR_CONTEXT(rift_area, area);
	struct area_addr addr, *addrp = NULL;
	struct listnode *node;
	uint8_t buff[255];

	addr.addr_len = dotformat2buff(buff, net_title);
	if (addr.addr_len < 8 || addr.addr_len > 20) {
		vty_out(vty,
			"Unsupported area address length %d, should be 8...20 \n",
			addr.addr_len);
		return CMD_WARNING_CONFIG_FAILED;
	}

	memcpy(addr.area_addr, buff, (int)addr.addr_len);

	for (ALL_LIST_ELEMENTS_RO(area->area_addrs, node, addrp))
		if ((addrp->addr_len + RIFT_SYS_ID_LEN + 1) == addr.addr_len
		    && !memcmp(addrp->area_addr, addr.area_addr, addr.addr_len))
			break;

	if (!addrp) {
		vty_out(vty, "No area address %s for area %s \n", net_title,
			area->area_tag);
		return CMD_ERR_NO_MATCH;
	}

	listnode_delete(area->area_addrs, addrp);
	XFREE(MTYPE_RIFT_AREA_ADDR, addrp);

	/*
	 * Last area address - reset the SystemID for this router
	 */
	if (listcount(area->area_addrs) == 0) {
		memset(rift->sysid, 0, RIFT_SYS_ID_LEN);
		rift->sysid_set = 0;
		if (rift->debugs & DEBUG_EVENTS)
			zlog_debug("Router has no SystemID");
	}

	return CMD_SUCCESS;
}

/*
 * 'show rift interface' command
 */

int show_rift_interface_common(struct vty *vty, const char *ifname, char detail)
{
	struct listnode *anode, *cnode;
	struct rift_area *area;
	struct rift_circuit *circuit;

	if (!rift) {
		vty_out(vty, "RIFT Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	for (ALL_LIST_ELEMENTS_RO(rift->area_list, anode, area)) {
		vty_out(vty, "Area %s:\n", area->area_tag);

		if (detail == RIFT_UI_LEVEL_BRIEF)
			vty_out(vty,
				"  Interface   CircId   State    Type     Level\n");

		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit))
			if (!ifname)
				rift_circuit_print_vty(circuit, vty, detail);
			else if (strcmp(circuit->interface->name, ifname) == 0)
				rift_circuit_print_vty(circuit, vty, detail);
	}

	return CMD_SUCCESS;
}

DEFUN (show_rift_interface,
       show_rift_interface_cmd,
       "show " PROTO_NAME " interface",
       SHOW_STR
       PROTO_HELP
       "RIFT interface\n")
{
	return show_rift_interface_common(vty, NULL, RIFT_UI_LEVEL_BRIEF);
}

DEFUN (show_rift_interface_detail,
       show_rift_interface_detail_cmd,
       "show " PROTO_NAME " interface detail",
       SHOW_STR
       PROTO_HELP
       "RIFT interface\n"
       "show detailed information\n")
{
	return show_rift_interface_common(vty, NULL, RIFT_UI_LEVEL_DETAIL);
}

DEFUN (show_rift_interface_arg,
       show_rift_interface_arg_cmd,
       "show " PROTO_NAME " interface WORD",
       SHOW_STR
       PROTO_HELP
       "RIFT interface\n"
       "RIFT interface name\n")
{
	int idx_word = 3;
	return show_rift_interface_common(vty, argv[idx_word]->arg,
					  RIFT_UI_LEVEL_DETAIL);
}

/*
 * 'show rift neighbor' command
 */

int show_rift_neighbor_common(struct vty *vty, const char *id, char detail)
{
	struct listnode *anode, *cnode, *node;
	struct rift_area *area;
	struct rift_circuit *circuit;
	struct list *adjdb;
	struct rift_adjacency *adj;
	struct rift_dynhn *dynhn;
	uint8_t sysid[RIFT_SYS_ID_LEN];
	int i;

	if (!rift) {
		vty_out(vty, "RIFT Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	memset(sysid, 0, RIFT_SYS_ID_LEN);
	if (id) {
		if (sysid2buff(sysid, id) == 0) {
			dynhn = dynhn_find_by_name(id);
			if (dynhn == NULL) {
				vty_out(vty, "Invalid system id %s\n", id);
				return CMD_SUCCESS;
			}
			memcpy(sysid, dynhn->id, RIFT_SYS_ID_LEN);
		}
	}

	for (ALL_LIST_ELEMENTS_RO(rift->area_list, anode, area)) {
		vty_out(vty, "Area %s:\n", area->area_tag);

		if (detail == RIFT_UI_LEVEL_BRIEF)
			vty_out(vty,
				"  System Id           Interface   L  State        Holdtime SNPA\n");

		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit)) {
			if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
				for (i = 0; i < 2; i++) {
					adjdb = circuit->u.bc.adjdb[i];
					if (adjdb && adjdb->count) {
						for (ALL_LIST_ELEMENTS_RO(
							     adjdb, node, adj))
							if (!id
							    || !memcmp(adj->sysid,
								       sysid,
								       RIFT_SYS_ID_LEN))
								rift_adj_print_vty(
									adj,
									vty,
									detail);
					}
				}
			} else if (circuit->circ_type == CIRCUIT_T_P2P
				   && circuit->u.p2p.neighbor) {
				adj = circuit->u.p2p.neighbor;
				if (!id
				    || !memcmp(adj->sysid, sysid,
					       RIFT_SYS_ID_LEN))
					rift_adj_print_vty(adj, vty, detail);
			}
		}
	}

	return CMD_SUCCESS;
}

/*
 * 'clear rift neighbor' command
 */
int clear_rift_neighbor_common(struct vty *vty, const char *id)
{
	struct listnode *anode, *cnode, *cnextnode, *node, *nnode;
	struct rift_area *area;
	struct rift_circuit *circuit;
	struct list *adjdb;
	struct rift_adjacency *adj;
	struct rift_dynhn *dynhn;
	uint8_t sysid[RIFT_SYS_ID_LEN];
	int i;

	if (!rift) {
		vty_out(vty, "RIFT Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	memset(sysid, 0, RIFT_SYS_ID_LEN);
	if (id) {
		if (sysid2buff(sysid, id) == 0) {
			dynhn = dynhn_find_by_name(id);
			if (dynhn == NULL) {
				vty_out(vty, "Invalid system id %s\n", id);
				return CMD_SUCCESS;
			}
			memcpy(sysid, dynhn->id, RIFT_SYS_ID_LEN);
		}
	}

	for (ALL_LIST_ELEMENTS_RO(rift->area_list, anode, area)) {
		for (ALL_LIST_ELEMENTS(area->circuit_list, cnode, cnextnode,
				       circuit)) {
			if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
				for (i = 0; i < 2; i++) {
					adjdb = circuit->u.bc.adjdb[i];
					if (adjdb && adjdb->count) {
						for (ALL_LIST_ELEMENTS(
							     adjdb, node, nnode,
							     adj))
							if (!id
							    || !memcmp(adj->sysid,
								       sysid,
								       RIFT_SYS_ID_LEN))
								rift_adj_state_change(
									adj,
									RIFT_ADJ_DOWN,
									"clear user request");
					}
				}
			} else if (circuit->circ_type == CIRCUIT_T_P2P
				   && circuit->u.p2p.neighbor) {
				adj = circuit->u.p2p.neighbor;
				if (!id
				    || !memcmp(adj->sysid, sysid,
					       RIFT_SYS_ID_LEN))
					rift_adj_state_change(
						adj, RIFT_ADJ_DOWN,
						"clear user request");
			}
		}
	}

	return CMD_SUCCESS;
}

DEFUN (show_rift_neighbor,
       show_rift_neighbor_cmd,
       "show " PROTO_NAME " neighbor",
       SHOW_STR
       PROTO_HELP
       "RIFT neighbor adjacencies\n")
{
	return show_rift_neighbor_common(vty, NULL, RIFT_UI_LEVEL_BRIEF);
}

DEFUN (show_rift_neighbor_detail,
       show_rift_neighbor_detail_cmd,
       "show " PROTO_NAME " neighbor detail",
       SHOW_STR
       PROTO_HELP
       "RIFT neighbor adjacencies\n"
       "show detailed information\n")
{
	return show_rift_neighbor_common(vty, NULL, RIFT_UI_LEVEL_DETAIL);
}

DEFUN (show_rift_neighbor_arg,
       show_rift_neighbor_arg_cmd,
       "show " PROTO_NAME " neighbor WORD",
       SHOW_STR
       PROTO_HELP
       "RIFT neighbor adjacencies\n"
       "System id\n")
{
	int idx_word = 3;
	return show_rift_neighbor_common(vty, argv[idx_word]->arg,
					 RIFT_UI_LEVEL_DETAIL);
}

DEFUN (clear_rift_neighbor,
       clear_rift_neighbor_cmd,
       "clear " PROTO_NAME " neighbor",
       CLEAR_STR
       PROTO_HELP
       "RIFT neighbor adjacencies\n")
{
	return clear_rift_neighbor_common(vty, NULL);
}

DEFUN (clear_rift_neighbor_arg,
       clear_rift_neighbor_arg_cmd,
       "clear " PROTO_NAME " neighbor WORD",
       CLEAR_STR
       PROTO_HELP
       "RIFT neighbor adjacencies\n"
       "System id\n")
{
	int idx_word = 3;
	return clear_rift_neighbor_common(vty, argv[idx_word]->arg);
}

/*
 * 'rift debug', 'show debugging'
 */
void print_debug(struct vty *vty, int flags, int onoff)
{
	char onoffs[4];
	if (onoff)
		strcpy(onoffs, "on");
	else
		strcpy(onoffs, "off");

	if (flags & DEBUG_ADJ_PACKETS)
		vty_out(vty,
			"RIFT Adjacency related packets debugging is %s\n",
			onoffs);
	if (flags & DEBUG_TX_QUEUE)
		vty_out(vty, "RIFT TX queue debugging is %s\n",
			onoffs);
	if (flags & DEBUG_SNP_PACKETS)
		vty_out(vty, "RIFT CSNP/PSNP packets debugging is %s\n",
			onoffs);
	if (flags & DEBUG_SPF_EVENTS)
		vty_out(vty, "RIFT SPF events debugging is %s\n", onoffs);
	if (flags & DEBUG_UPDATE_PACKETS)
		vty_out(vty, "RIFT Update related packet debugging is %s\n",
			onoffs);
	if (flags & DEBUG_RTE_EVENTS)
		vty_out(vty, "RIFT Route related debuggin is %s\n", onoffs);
	if (flags & DEBUG_EVENTS)
		vty_out(vty, "RIFT Event debugging is %s\n", onoffs);
	if (flags & DEBUG_PACKET_DUMP)
		vty_out(vty, "RIFT Packet dump debugging is %s\n", onoffs);
	if (flags & DEBUG_LSP_GEN)
		vty_out(vty, "RIFT LSP generation debugging is %s\n", onoffs);
	if (flags & DEBUG_LSP_SCHED)
		vty_out(vty, "RIFT LSP scheduling debugging is %s\n", onoffs);
	if (flags & DEBUG_FLOODING)
		vty_out(vty, "RIFT Flooding debugging is %s\n", onoffs);
	if (flags & DEBUG_BFD)
		vty_out(vty, "RIFT BFD debugging is %s\n", onoffs);
}

DEFUN_NOSH (show_debugging,
	    show_debugging_rift_cmd,
	    "show debugging [" PROTO_NAME "]",
	    SHOW_STR
	    "State of each debugging option\n"
	    PROTO_HELP)
{
	vty_out(vty, PROTO_NAME " debugging status:\n");

	if (rift->debugs)
		print_debug(vty, rift->debugs, 1);

	return CMD_SUCCESS;
}

/* Debug node. */
static struct cmd_node debug_node = {DEBUG_NODE, "", 1};

static int config_write_debug(struct vty *vty)
{
	int write = 0;
	int flags = rift->debugs;

	if (flags & DEBUG_ADJ_PACKETS) {
		vty_out(vty, "debug " PROTO_NAME " adj-packets\n");
		write++;
	}
	if (flags & DEBUG_TX_QUEUE) {
		vty_out(vty, "debug " PROTO_NAME " tx-queue\n");
		write++;
	}
	if (flags & DEBUG_SNP_PACKETS) {
		vty_out(vty, "debug " PROTO_NAME " snp-packets\n");
		write++;
	}
	if (flags & DEBUG_SPF_EVENTS) {
		vty_out(vty, "debug " PROTO_NAME " spf-events\n");
		write++;
	}
	if (flags & DEBUG_UPDATE_PACKETS) {
		vty_out(vty, "debug " PROTO_NAME " update-packets\n");
		write++;
	}
	if (flags & DEBUG_RTE_EVENTS) {
		vty_out(vty, "debug " PROTO_NAME " route-events\n");
		write++;
	}
	if (flags & DEBUG_EVENTS) {
		vty_out(vty, "debug " PROTO_NAME " events\n");
		write++;
	}
	if (flags & DEBUG_PACKET_DUMP) {
		vty_out(vty, "debug " PROTO_NAME " packet-dump\n");
		write++;
	}
	if (flags & DEBUG_LSP_GEN) {
		vty_out(vty, "debug " PROTO_NAME " lsp-gen\n");
		write++;
	}
	if (flags & DEBUG_LSP_SCHED) {
		vty_out(vty, "debug " PROTO_NAME " lsp-sched\n");
		write++;
	}
	if (flags & DEBUG_FLOODING) {
		vty_out(vty, "debug " PROTO_NAME " flooding\n");
		write++;
	}
	if (flags & DEBUG_BFD) {
		vty_out(vty, "debug " PROTO_NAME " bfd\n");
		write++;
	}
	write += spf_backoff_write_config(vty);

	return write;
}

DEFUN (debug_rift_adj,
       debug_rift_adj_cmd,
       "debug " PROTO_NAME " adj-packets",
       DEBUG_STR
       PROTO_HELP
       "RIFT Adjacency related packets\n")
{
	rift->debugs |= DEBUG_ADJ_PACKETS;
	print_debug(vty, DEBUG_ADJ_PACKETS, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_rift_adj,
       no_debug_rift_adj_cmd,
       "no debug " PROTO_NAME " adj-packets",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "RIFT Adjacency related packets\n")
{
	rift->debugs &= ~DEBUG_ADJ_PACKETS;
	print_debug(vty, DEBUG_ADJ_PACKETS, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_rift_tx_queue,
       debug_rift_tx_queue_cmd,
       "debug " PROTO_NAME " tx-queue",
       DEBUG_STR
       PROTO_HELP
       "RIFT TX queues\n")
{
	rift->debugs |= DEBUG_TX_QUEUE;
	print_debug(vty, DEBUG_TX_QUEUE, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_rift_tx_queue,
       no_debug_rift_tx_queue_cmd,
       "no debug " PROTO_NAME " tx-queue",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "RIFT TX queues\n")
{
	rift->debugs &= ~DEBUG_TX_QUEUE;
	print_debug(vty, DEBUG_TX_QUEUE, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_rift_flooding,
       debug_rift_flooding_cmd,
       "debug " PROTO_NAME " flooding",
       DEBUG_STR
       PROTO_HELP
       "Flooding algorithm\n")
{
	rift->debugs |= DEBUG_FLOODING;
	print_debug(vty, DEBUG_FLOODING, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_rift_flooding,
       no_debug_rift_flooding_cmd,
       "no debug " PROTO_NAME " flooding",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "Flooding algorithm\n")
{
	rift->debugs &= ~DEBUG_FLOODING;
	print_debug(vty, DEBUG_FLOODING, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_rift_snp,
       debug_rift_snp_cmd,
       "debug " PROTO_NAME " snp-packets",
       DEBUG_STR
       PROTO_HELP
       "RIFT CSNP/PSNP packets\n")
{
	rift->debugs |= DEBUG_SNP_PACKETS;
	print_debug(vty, DEBUG_SNP_PACKETS, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_rift_snp,
       no_debug_rift_snp_cmd,
       "no debug " PROTO_NAME " snp-packets",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "RIFT CSNP/PSNP packets\n")
{
	rift->debugs &= ~DEBUG_SNP_PACKETS;
	print_debug(vty, DEBUG_SNP_PACKETS, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_rift_upd,
       debug_rift_upd_cmd,
       "debug " PROTO_NAME " update-packets",
       DEBUG_STR
       PROTO_HELP
       "RIFT Update related packets\n")
{
	rift->debugs |= DEBUG_UPDATE_PACKETS;
	print_debug(vty, DEBUG_UPDATE_PACKETS, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_rift_upd,
       no_debug_rift_upd_cmd,
       "no debug " PROTO_NAME " update-packets",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "RIFT Update related packets\n")
{
	rift->debugs &= ~DEBUG_UPDATE_PACKETS;
	print_debug(vty, DEBUG_UPDATE_PACKETS, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_rift_spfevents,
       debug_rift_spfevents_cmd,
       "debug " PROTO_NAME " spf-events",
       DEBUG_STR
       PROTO_HELP
       "RIFT Shortest Path First Events\n")
{
	rift->debugs |= DEBUG_SPF_EVENTS;
	print_debug(vty, DEBUG_SPF_EVENTS, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_rift_spfevents,
       no_debug_rift_spfevents_cmd,
       "no debug " PROTO_NAME " spf-events",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "RIFT Shortest Path First Events\n")
{
	rift->debugs &= ~DEBUG_SPF_EVENTS;
	print_debug(vty, DEBUG_SPF_EVENTS, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_rift_rtevents,
       debug_rift_rtevents_cmd,
       "debug " PROTO_NAME " route-events",
       DEBUG_STR
       PROTO_HELP
       "RIFT Route related events\n")
{
	rift->debugs |= DEBUG_RTE_EVENTS;
	print_debug(vty, DEBUG_RTE_EVENTS, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_rift_rtevents,
       no_debug_rift_rtevents_cmd,
       "no debug " PROTO_NAME " route-events",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "RIFT Route related events\n")
{
	rift->debugs &= ~DEBUG_RTE_EVENTS;
	print_debug(vty, DEBUG_RTE_EVENTS, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_rift_events,
       debug_rift_events_cmd,
       "debug " PROTO_NAME " events",
       DEBUG_STR
       PROTO_HELP
       "RIFT Events\n")
{
	rift->debugs |= DEBUG_EVENTS;
	print_debug(vty, DEBUG_EVENTS, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_rift_events,
       no_debug_rift_events_cmd,
       "no debug " PROTO_NAME " events",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "RIFT Events\n")
{
	rift->debugs &= ~DEBUG_EVENTS;
	print_debug(vty, DEBUG_EVENTS, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_rift_packet_dump,
       debug_rift_packet_dump_cmd,
       "debug " PROTO_NAME " packet-dump",
       DEBUG_STR
       PROTO_HELP
       "RIFT packet dump\n")
{
	rift->debugs |= DEBUG_PACKET_DUMP;
	print_debug(vty, DEBUG_PACKET_DUMP, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_rift_packet_dump,
       no_debug_rift_packet_dump_cmd,
       "no debug " PROTO_NAME " packet-dump",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "RIFT packet dump\n")
{
	rift->debugs &= ~DEBUG_PACKET_DUMP;
	print_debug(vty, DEBUG_PACKET_DUMP, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_rift_lsp_gen,
       debug_rift_lsp_gen_cmd,
       "debug " PROTO_NAME " lsp-gen",
       DEBUG_STR
       PROTO_HELP
       "RIFT generation of own LSPs\n")
{
	rift->debugs |= DEBUG_LSP_GEN;
	print_debug(vty, DEBUG_LSP_GEN, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_rift_lsp_gen,
       no_debug_rift_lsp_gen_cmd,
       "no debug " PROTO_NAME " lsp-gen",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "RIFT generation of own LSPs\n")
{
	rift->debugs &= ~DEBUG_LSP_GEN;
	print_debug(vty, DEBUG_LSP_GEN, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_rift_lsp_sched,
       debug_rift_lsp_sched_cmd,
       "debug " PROTO_NAME " lsp-sched",
       DEBUG_STR
       PROTO_HELP
       "RIFT scheduling of LSP generation\n")
{
	rift->debugs |= DEBUG_LSP_SCHED;
	print_debug(vty, DEBUG_LSP_SCHED, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_rift_lsp_sched,
       no_debug_rift_lsp_sched_cmd,
       "no debug " PROTO_NAME " lsp-sched",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       "RIFT scheduling of LSP generation\n")
{
	rift->debugs &= ~DEBUG_LSP_SCHED;
	print_debug(vty, DEBUG_LSP_SCHED, 0);

	return CMD_SUCCESS;
}

DEFUN (debug_rift_bfd,
       debug_rift_bfd_cmd,
       "debug " PROTO_NAME " bfd",
       DEBUG_STR
       PROTO_HELP
       PROTO_NAME " interaction with BFD\n")
{
	rift->debugs |= DEBUG_BFD;
	print_debug(vty, DEBUG_BFD, 1);

	return CMD_SUCCESS;
}

DEFUN (no_debug_rift_bfd,
       no_debug_rift_bfd_cmd,
       "no debug " PROTO_NAME " bfd",
       NO_STR
       UNDEBUG_STR
       PROTO_HELP
       PROTO_NAME " interaction with BFD\n")
{
	rift->debugs &= ~DEBUG_BFD;
	print_debug(vty, DEBUG_BFD, 0);

	return CMD_SUCCESS;
}

DEFUN (show_rift_hostname,
       show_rift_hostname_cmd,
       "show " PROTO_NAME " hostname",
       SHOW_STR
       PROTO_HELP
       "RIFT Dynamic hostname mapping\n")
{
	dynhn_print_all(vty);

	return CMD_SUCCESS;
}

DEFUN (show_rift_spf_ietf,
       show_rift_spf_ietf_cmd,
       "show " PROTO_NAME " spf-delay-ietf",
       SHOW_STR
       PROTO_HELP
       "SPF delay IETF information\n")
{
	if (!rift) {
		vty_out(vty, "RIFT is not running\n");
		return CMD_SUCCESS;
	}

	struct listnode *node;
	struct rift_area *area;

	for (ALL_LIST_ELEMENTS_RO(rift->area_list, node, area)) {
		vty_out(vty, "Area %s:\n",
			area->area_tag ? area->area_tag : "null");

		for (int level = RIFT_LEVEL1; level <= RIFT_LEVELS; level++) {
			if ((area->is_type & level) == 0)
				continue;

			vty_out(vty, "  Level-%d:\n", level);
			vty_out(vty, "    SPF delay status: ");
			if (area->spf_timer[level - 1]) {
				struct timeval remain = thread_timer_remain(
					area->spf_timer[level - 1]);
				vty_out(vty, "Pending, due in %lld msec\n",
					(long long)remain.tv_sec * 1000
						+ remain.tv_usec / 1000);
			} else {
				vty_out(vty, "Not scheduled\n");
			}

			if (area->spf_delay_ietf[level - 1]) {
				vty_out(vty,
					"    Using draft-ietf-rtgwg-backoff-algo-04\n");
				spf_backoff_show(
					area->spf_delay_ietf[level - 1], vty,
					"    ");
			} else {
				vty_out(vty, "    Using legacy backoff algo\n");
			}
		}
	}
	return CMD_SUCCESS;
}

DEFUN (show_rift_summary,
       show_rift_summary_cmd,
       "show " PROTO_NAME " summary",
       SHOW_STR PROTO_HELP "summary\n")
{
	struct listnode *node, *node2;
	struct rift_area *area;
	int level;

	if (rift == NULL) {
		vty_out(vty, PROTO_NAME " is not running\n");
		return CMD_SUCCESS;
	}

	vty_out(vty, "Process Id      : %ld\n", rift->process_id);
	if (rift->sysid_set)
		vty_out(vty, "System Id       : %s\n",
			sysid_print(rift->sysid));

	vty_out(vty, "Up time         : ");
	vty_out_timestr(vty, rift->uptime);
	vty_out(vty, "\n");

	if (rift->area_list)
		vty_out(vty, "Number of areas : %d\n", rift->area_list->count);

	for (ALL_LIST_ELEMENTS_RO(rift->area_list, node, area)) {
		vty_out(vty, "Area %s:\n",
			area->area_tag ? area->area_tag : "null");

		/* TODO
		if (f...abricd) {
			uint8_t tier = f...abricd_tier(area);
			if (tier == RIFT_TIER_UNDEFINED)
				vty_out(vty, "  Tier: undefined\n");
			else
				vty_out(vty, "  Tier: %" PRIu8 "\n", tier);
		}
		*/

		if (listcount(area->area_addrs) > 0) {
			struct area_addr *area_addr;
			for (ALL_LIST_ELEMENTS_RO(area->area_addrs, node2,
						  area_addr)) {
				vty_out(vty, "  Net: %s\n",
					isonet_print(area_addr->area_addr,
						     area_addr->addr_len
							     + RIFT_SYS_ID_LEN
							     + 1));
			}
		}

		vty_out(vty, "  TX counters per PDU type:\n");
		pdu_counter_print(vty, "    ", area->pdu_tx_counters);
		vty_out(vty, "   LSP RXMT: %" PRIu64 "\n",
			area->lsp_rxmt_count);
		vty_out(vty, "  RX counters per PDU type:\n");
		pdu_counter_print(vty, "    ", area->pdu_rx_counters);

		for (level = RIFT_LEVEL1; level <= RIFT_LEVELS; level++) {
			if ((area->is_type & level) == 0)
				continue;

			vty_out(vty, "  Level-%d:\n", level);

			vty_out(vty, "    LSP0 regenerated: %" PRIu64 "\n",
				area->lsp_gen_count[level - 1]);

			vty_out(vty, "         LSPs purged: %" PRIu64 "\n",
				area->lsp_purge_count[level - 1]);

			if (area->spf_timer[level - 1])
				vty_out(vty, "    SPF: (pending)\n");
			else
				vty_out(vty, "    SPF:\n");

			vty_out(vty, "      minimum interval  : %d",
				area->min_spf_interval[level - 1]);
			if (area->spf_delay_ietf[level - 1])
				vty_out(vty,
					" (not used, IETF SPF delay activated)");
			vty_out(vty, "\n");

			vty_out(vty, "    IPv4 route computation:\n");
			rift_spf_print(area->spftree[SPFTREE_IPV4][level - 1],
				       vty);

			vty_out(vty, "    IPv6 route computation:\n");
			rift_spf_print(area->spftree[SPFTREE_IPV6][level - 1],
				       vty);

			vty_out(vty, "    IPv6 dst-src route computation:\n");
			rift_spf_print(area->spftree[SPFTREE_DSTSRC][level-1],
				       vty);
		}
	}
	vty_out(vty, "\n");

	return CMD_SUCCESS;
}

struct rift_lsp *lsp_for_arg(const char *argv, dict_t *lspdb)
{
	char sysid[255] = {0};
	uint8_t number[3];
	const char *pos;
	uint8_t lspid[RIFT_SYS_ID_LEN + 2] = {0};
	struct rift_dynhn *dynhn;
	struct rift_lsp *lsp = NULL;

	if (!argv)
		return NULL;

	/*
	 * extract fragment and pseudo id from the string argv
	 * in the forms:
	 * (a) <systemid/hostname>.<pseudo-id>-<framenent> or
	 * (b) <systemid/hostname>.<pseudo-id> or
	 * (c) <systemid/hostname> or
	 * Where systemid is in the form:
	 * xxxx.xxxx.xxxx
	 */
	if (argv)
		strlcpy(sysid, argv, sizeof(sysid));
	if (argv && strlen(argv) > 3) {
		pos = argv + strlen(argv) - 3;
		if (strncmp(pos, "-", 1) == 0) {
			memcpy(number, ++pos, 2);
			lspid[RIFT_SYS_ID_LEN + 1] =
				(uint8_t)strtol((char *)number, NULL, 16);
			pos -= 4;
			if (strncmp(pos, ".", 1) != 0)
				return NULL;
		}
		if (strncmp(pos, ".", 1) == 0) {
			memcpy(number, ++pos, 2);
			lspid[RIFT_SYS_ID_LEN] =
				(uint8_t)strtol((char *)number, NULL, 16);
			sysid[pos - argv - 1] = '\0';
		}
	}

	/*
	 * Try to find the lsp-id if the argv
	 * string is in
	 * the form
	 * hostname.<pseudo-id>-<fragment>
	 */
	if (sysid2buff(lspid, sysid)) {
		lsp = lsp_search(lspid, lspdb);
	} else if ((dynhn = dynhn_find_by_name(sysid))) {
		memcpy(lspid, dynhn->id, RIFT_SYS_ID_LEN);
		lsp = lsp_search(lspid, lspdb);
	} else if (strncmp(cmd_hostname_get(), sysid, 15) == 0) {
		memcpy(lspid, rift->sysid, RIFT_SYS_ID_LEN);
		lsp = lsp_search(lspid, lspdb);
	}

	return lsp;
}

/*
 * This function supports following display options:
 * [ show rift database [detail] ]
 * [ show rift database <sysid> [detail] ]
 * [ show rift database <hostname> [detail] ]
 * [ show rift database <sysid>.<pseudo-id> [detail] ]
 * [ show rift database <hostname>.<pseudo-id> [detail] ]
 * [ show rift database <sysid>.<pseudo-id>-<fragment-number> [detail] ]
 * [ show rift database <hostname>.<pseudo-id>-<fragment-number> [detail] ]
 * [ show rift database detail <sysid> ]
 * [ show rift database detail <hostname> ]
 * [ show rift database detail <sysid>.<pseudo-id> ]
 * [ show rift database detail <hostname>.<pseudo-id> ]
 * [ show rift database detail <sysid>.<pseudo-id>-<fragment-number> ]
 * [ show rift database detail <hostname>.<pseudo-id>-<fragment-number> ]
 */
/* TODO: Is do_ appropriate? */
static int do_show_rift_database(struct vty *vty, const char *argv, int ui_level)
{
	struct listnode *node;
	struct rift_area *area;
	struct rift_lsp *lsp;
	int level, lsp_count;

	if (rift->area_list->count == 0)
		return CMD_SUCCESS;

	for (ALL_LIST_ELEMENTS_RO(rift->area_list, node, area)) {
		vty_out(vty, "Area %s:\n",
			area->area_tag ? area->area_tag : "null");

		for (level = 0; level < RIFT_LEVELS; level++) {
			if (area->lspdb[level]
			    && dict_count(area->lspdb[level]) > 0) {
				lsp = lsp_for_arg(argv, area->lspdb[level]);

				if (lsp != NULL || argv == NULL) {
					vty_out(vty,
						"RIFT Level-%d link-state database:\n",
						level + 1);

					/* print the title in all cases */
					vty_out(vty,
						"LSP ID                  PduLen  SeqNumber   Chksum  Holdtime  ATT/P/OL\n");
				}

				if (lsp) {
					if (ui_level == RIFT_UI_LEVEL_DETAIL)
						lsp_print_detail(
							lsp, vty,
							area->dynhostname);
					else
						lsp_print(lsp, vty,
							  area->dynhostname);
				} else if (argv == NULL) {
					lsp_count = lsp_print_all(
						vty, area->lspdb[level],
						ui_level, area->dynhostname);

					vty_out(vty, "    %u LSPs\n\n",
						lsp_count);
				}
			}
		}
	}

	return CMD_SUCCESS;
}

DEFUN (show_rift_database,
       show_rift_database_cmd,
       "show " PROTO_NAME " database [detail] [WORD]",
       SHOW_STR
       PROTO_HELP
       "Link state database\n"
       "Detailed information\n"
       "LSP ID\n")
{
	int idx = 0;
	int uilevel = argv_find(argv, argc, "detail", &idx)
			      ? RIFT_UI_LEVEL_DETAIL
			      : RIFT_UI_LEVEL_BRIEF;
	char *id = argv_find(argv, argc, "WORD", &idx) ? argv[idx]->arg : NULL;
	return do_show_rift_database(vty, id, uilevel);
}

void rift_area_lsp_mtu_set(struct rift_area *area, unsigned int lsp_mtu)
{
	area->lsp_mtu = lsp_mtu;
	lsp_regenerate_schedule(area, IS_LEVEL_1_AND_2, 1);
}

static int rift_area_passwd_set(struct rift_area *area, int level,
				uint8_t passwd_type, const char *passwd,
				uint8_t snp_auth)
{
	struct rift_passwd *dest;
	struct rift_passwd modified;
	int len;

	assert((level == IS_LEVEL_1) || (level == IS_LEVEL_2));
	dest = (level == IS_LEVEL_1) ? &area->area_passwd
				     : &area->domain_passwd;
	memset(&modified, 0, sizeof(modified));

	if (passwd_type != RIFT_PASSWD_TYPE_UNUSED) {
		if (!passwd)
			return -1;

		len = strlen(passwd);
		if (len > 254)
			return -1;

		modified.len = len;
		strlcpy((char *)modified.passwd, passwd,
			sizeof(modified.passwd));
		modified.type = passwd_type;
		modified.snp_auth = snp_auth;
	}

	if (memcmp(&modified, dest, sizeof(modified))) {
		memcpy(dest, &modified, sizeof(modified));
		lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 1);
	}

	return 0;
}

int rift_area_passwd_unset(struct rift_area *area, int level)
{
	return rift_area_passwd_set(area, level, RIFT_PASSWD_TYPE_UNUSED, NULL,
				    0);
}

int rift_area_passwd_cleartext_set(struct rift_area *area, int level,
				   const char *passwd, uint8_t snp_auth)
{
	return rift_area_passwd_set(area, level, RIFT_PASSWD_TYPE_CLEARTXT,
				    passwd, snp_auth);
}

int rift_area_passwd_hmac_md5_set(struct rift_area *area, int level,
				  const char *passwd, uint8_t snp_auth)
{
	return rift_area_passwd_set(area, level, RIFT_PASSWD_TYPE_HMAC_MD5,
				    passwd, snp_auth);
}

void rift_area_invalidate_routes(struct rift_area *area, int levels)
{
	for (int level = RIFT_LEVEL1; level <= RIFT_LEVEL2; level++) {
		if (!(level & levels))
			continue;
		for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++) {
			rift_spf_invalidate_routes(
					area->spftree[tree][level - 1]);
		}
	}
}

void rift_area_verify_routes(struct rift_area *area)
{
	for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++)
		rift_spf_verify_routes(area, area->spftree[tree]);
}

static void area_resign_level(struct rift_area *area, int level)
{
	rift_area_invalidate_routes(area, level);
	rift_area_verify_routes(area);

	if (area->lspdb[level - 1]) {
		lsp_db_destroy(area->lspdb[level - 1]);
		area->lspdb[level - 1] = NULL;
	}

	for (int tree = SPFTREE_IPV4; tree < SPFTREE_COUNT; tree++) {
		if (area->spftree[tree][level - 1]) {
			rift_spftree_del(area->spftree[tree][level - 1]);
			area->spftree[tree][level - 1] = NULL;
		}
	}

	THREAD_TIMER_OFF(area->spf_timer[level - 1]);

	sched_debug(
		"RIFT (%s): Resigned from L%d - canceling LSP regeneration timer.",
		area->area_tag, level);
	THREAD_TIMER_OFF(area->t_lsp_refresh[level - 1]);
	area->lsp_regenerate_pending[level - 1] = 0;
}

void rift_area_is_type_set(struct rift_area *area, int is_type)
{
	struct listnode *node;
	struct rift_circuit *circuit;

	if (rift->debugs & DEBUG_EVENTS)
		zlog_debug("RIFT-Evt (%s) system type change %s -> %s",
			   area->area_tag, circuit_t2string(area->is_type),
			   circuit_t2string(is_type));

	if (area->is_type == is_type)
		return; /* No change */

	switch (area->is_type) {
	case IS_LEVEL_1:
		if (is_type == IS_LEVEL_2)
			area_resign_level(area, IS_LEVEL_1);

		if (area->lspdb[1] == NULL)
			area->lspdb[1] = lsp_db_init();
		break;

	case IS_LEVEL_1_AND_2:
		if (is_type == IS_LEVEL_1)
			area_resign_level(area, IS_LEVEL_2);
		else
			area_resign_level(area, IS_LEVEL_1);
		break;

	case IS_LEVEL_2:
		if (is_type == IS_LEVEL_1)
			area_resign_level(area, IS_LEVEL_2);

		if (area->lspdb[0] == NULL)
			area->lspdb[0] = lsp_db_init();
		break;

	default:
		break;
	}

	area->is_type = is_type;

	/* override circuit's is_type */
	if (area->is_type != IS_LEVEL_1_AND_2) {
		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
			rift_circuit_is_type_set(circuit, is_type);
	}

	spftree_area_init(area);

	if (listcount(area->area_addrs) > 0) {
		if (is_type & IS_LEVEL_1)
			lsp_generate(area, IS_LEVEL_1);
		if (is_type & IS_LEVEL_2)
			lsp_generate(area, IS_LEVEL_2);
	}
	lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 1);

	return;
}

void rift_area_metricstyle_set(struct rift_area *area, bool old_metric,
			       bool new_metric)
{
	area->oldmetric = old_metric;
	area->newmetric = new_metric;
	lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 1);
}

void rift_area_overload_bit_set(struct rift_area *area, bool overload_bit)
{
	char new_overload_bit = overload_bit ? LSPBIT_OL : 0;

	if (new_overload_bit != area->overload_bit) {
		area->overload_bit = new_overload_bit;
		lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 1);
	}
	rift_notif_db_overload(area, overload_bit);
}

void rift_area_attached_bit_set(struct rift_area *area, bool attached_bit)
{
	char new_attached_bit = attached_bit ? LSPBIT_ATT : 0;

	if (new_attached_bit != area->attached_bit) {
		area->attached_bit = new_attached_bit;
		lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 1);
	}
}

void rift_area_dynhostname_set(struct rift_area *area, bool dynhostname)
{
	if (area->dynhostname != dynhostname) {
		area->dynhostname = dynhostname;
		lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 0);
	}
}

void rift_area_max_lsp_lifetime_set(struct rift_area *area, int level,
				    uint16_t max_lsp_lifetime)
{
	assert((level == IS_LEVEL_1) || (level == IS_LEVEL_2));

	if (area->max_lsp_lifetime[level - 1] == max_lsp_lifetime)
		return;

	area->max_lsp_lifetime[level - 1] = max_lsp_lifetime;
	lsp_regenerate_schedule(area, level, 1);
}

void rift_area_lsp_refresh_set(struct rift_area *area, int level,
			       uint16_t lsp_refresh)
{
	assert((level == IS_LEVEL_1) || (level == IS_LEVEL_2));

	if (area->lsp_refresh[level - 1] == lsp_refresh)
		return;

	area->lsp_refresh[level - 1] = lsp_refresh;
	lsp_regenerate_schedule(area, level, 1);
}

/* RIFT configuration write function */
int rift_config_write(struct vty *vty)
{
	int write = 0;
	struct lyd_node *dnode;

	dnode = yang_dnode_get(running_config->dnode, "/frr-riftd:rift");
	if (dnode) {
		nb_cli_show_dnode_cmds(vty, dnode, false);
		write++;
	}

	return write;
}

struct cmd_node router_node = {ROUTER_NODE, "%s(config-router)# ", 1};

void rift_init(void)
{
	/* Install RIFT top node */
	install_node(&router_node, rift_config_write);

	install_element(VIEW_NODE, &show_rift_summary_cmd);

	install_element(VIEW_NODE, &show_rift_spf_ietf_cmd);

	install_element(VIEW_NODE, &show_rift_interface_cmd);
	install_element(VIEW_NODE, &show_rift_interface_detail_cmd);
	install_element(VIEW_NODE, &show_rift_interface_arg_cmd);

	install_element(VIEW_NODE, &show_rift_neighbor_cmd);
	install_element(VIEW_NODE, &show_rift_neighbor_detail_cmd);
	install_element(VIEW_NODE, &show_rift_neighbor_arg_cmd);
	install_element(VIEW_NODE, &clear_rift_neighbor_cmd);
	install_element(VIEW_NODE, &clear_rift_neighbor_arg_cmd);

	install_element(VIEW_NODE, &show_rift_hostname_cmd);
	install_element(VIEW_NODE, &show_rift_database_cmd);

	install_element(ENABLE_NODE, &show_debugging_rift_cmd);

	install_node(&debug_node, config_write_debug);

	install_element(ENABLE_NODE, &debug_rift_adj_cmd);
	install_element(ENABLE_NODE, &no_debug_rift_adj_cmd);
	install_element(ENABLE_NODE, &debug_rift_tx_queue_cmd);
	install_element(ENABLE_NODE, &no_debug_rift_tx_queue_cmd);
	install_element(ENABLE_NODE, &debug_rift_flooding_cmd);
	install_element(ENABLE_NODE, &no_debug_rift_flooding_cmd);
	install_element(ENABLE_NODE, &debug_rift_snp_cmd);
	install_element(ENABLE_NODE, &no_debug_rift_snp_cmd);
	install_element(ENABLE_NODE, &debug_rift_upd_cmd);
	install_element(ENABLE_NODE, &no_debug_rift_upd_cmd);
	install_element(ENABLE_NODE, &debug_rift_spfevents_cmd);
	install_element(ENABLE_NODE, &no_debug_rift_spfevents_cmd);
	install_element(ENABLE_NODE, &debug_rift_rtevents_cmd);
	install_element(ENABLE_NODE, &no_debug_rift_rtevents_cmd);
	install_element(ENABLE_NODE, &debug_rift_events_cmd);
	install_element(ENABLE_NODE, &no_debug_rift_events_cmd);
	install_element(ENABLE_NODE, &debug_rift_packet_dump_cmd);
	install_element(ENABLE_NODE, &no_debug_rift_packet_dump_cmd);
	install_element(ENABLE_NODE, &debug_rift_lsp_gen_cmd);
	install_element(ENABLE_NODE, &no_debug_rift_lsp_gen_cmd);
	install_element(ENABLE_NODE, &debug_rift_lsp_sched_cmd);
	install_element(ENABLE_NODE, &no_debug_rift_lsp_sched_cmd);
	install_element(ENABLE_NODE, &debug_rift_bfd_cmd);
	install_element(ENABLE_NODE, &no_debug_rift_bfd_cmd);

	install_element(CONFIG_NODE, &debug_rift_adj_cmd);
	install_element(CONFIG_NODE, &no_debug_rift_adj_cmd);
	install_element(CONFIG_NODE, &debug_rift_tx_queue_cmd);
	install_element(CONFIG_NODE, &no_debug_rift_tx_queue_cmd);
	install_element(CONFIG_NODE, &debug_rift_flooding_cmd);
	install_element(CONFIG_NODE, &no_debug_rift_flooding_cmd);
	install_element(CONFIG_NODE, &debug_rift_snp_cmd);
	install_element(CONFIG_NODE, &no_debug_rift_snp_cmd);
	install_element(CONFIG_NODE, &debug_rift_upd_cmd);
	install_element(CONFIG_NODE, &no_debug_rift_upd_cmd);
	install_element(CONFIG_NODE, &debug_rift_spfevents_cmd);
	install_element(CONFIG_NODE, &no_debug_rift_spfevents_cmd);
	install_element(CONFIG_NODE, &debug_rift_rtevents_cmd);
	install_element(CONFIG_NODE, &no_debug_rift_rtevents_cmd);
	install_element(CONFIG_NODE, &debug_rift_events_cmd);
	install_element(CONFIG_NODE, &no_debug_rift_events_cmd);
	install_element(CONFIG_NODE, &debug_rift_packet_dump_cmd);
	install_element(CONFIG_NODE, &no_debug_rift_packet_dump_cmd);
	install_element(CONFIG_NODE, &debug_rift_lsp_gen_cmd);
	install_element(CONFIG_NODE, &no_debug_rift_lsp_gen_cmd);
	install_element(CONFIG_NODE, &debug_rift_lsp_sched_cmd);
	install_element(CONFIG_NODE, &no_debug_rift_lsp_sched_cmd);
	install_element(CONFIG_NODE, &debug_rift_bfd_cmd);
	install_element(CONFIG_NODE, &no_debug_rift_bfd_cmd);

	install_default(ROUTER_NODE);

	spf_backoff_cmd_init();
}
