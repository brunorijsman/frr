/*
 * RIFT Rout(e)ing protocol - rift_zebra.c
 *
 * Copyright (C) 2019        Bruno Rijsman
 *
 * This code is based on the original FRR IS-IS code, which is:
 * 
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 * Copyright (C) 2013-2015   Christian Franke <chris@opensourcerouting.org>
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
#include "command.h"
#include "memory.h"
#include "log.h"
#include "if.h"
#include "network.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "linklist.h"
#include "nexthop.h"
#include "vrf.h"
#include "libfrr.h"

#include "riftd/dict.h"
#include "riftd/rift_constants.h"
#include "riftd/rift_common.h"
#include "riftd/rift_flags.h"
#include "riftd/rift_misc.h"
#include "riftd/rift_circuit.h"
#include "riftd/riftd.h"
#include "riftd/rift_circuit.h"
#include "riftd/rift_csm.h"
#include "riftd/rift_lsp.h"
#include "riftd/rift_route.h"
#include "riftd/rift_zebra.h"
#include "riftd/rift_te.h"

struct zclient *zclient = NULL;

/* Router-id update message from zebra. */
static int rift_router_id_update_zebra(int command, struct zclient *zclient,
				       zebra_size_t length, vrf_id_t vrf_id)
{
	struct rift_area *area;
	struct listnode *node;
	struct prefix router_id;

	/*
	 * If RIFT TE is enable, TE Router ID is set through specific command.
	 * See mpls_te_router_addr() command in rift_te.c
	 */
	if (IS_MPLS_TE(riftMplsTE))
		return 0;

	zebra_router_id_update_read(zclient->ibuf, &router_id);
	if (rift->router_id == router_id.u.prefix4.s_addr)
		return 0;

	rift->router_id = router_id.u.prefix4.s_addr;
	for (ALL_LIST_ELEMENTS_RO(rift->area_list, node, area))
		if (listcount(area->area_addrs) > 0)
			lsp_regenerate_schedule(area, area->is_type, 0);

	return 0;
}

static int rift_zebra_if_add(int command, struct zclient *zclient,
			     zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);

	if (if_is_operative(ifp))
		rift_csm_state_change(IF_UP_FROM_Z, circuit_scan_by_ifp(ifp),
				      ifp);

	return 0;
}

static int rift_zebra_if_del(int command, struct zclient *zclient,
			     zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct stream *s;

	s = zclient->ibuf;
	ifp = zebra_interface_state_read(s, vrf_id);

	if (!ifp)
		return 0;

	if (if_is_operative(ifp))
		zlog_warn("Zebra: got delete of %s, but interface is still up",
			  ifp->name);

	rift_csm_state_change(IF_DOWN_FROM_Z, circuit_scan_by_ifp(ifp), ifp);

	/* Cannot call if_delete because we should retain the pseudo interface
	   in case there is configuration info attached to it. */
	if_delete_retain(ifp);

	if_set_index(ifp, IFINDEX_INTERNAL);

	return 0;
}

static int rift_zebra_if_state_up(int command, struct zclient *zclient,
				  zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);

	if (ifp == NULL)
		return 0;

	rift_csm_state_change(IF_UP_FROM_Z, circuit_scan_by_ifp(ifp), ifp);

	return 0;
}

static int rift_zebra_if_state_down(int command, struct zclient *zclient,
				    zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct rift_circuit *circuit;

	ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);

	if (ifp == NULL)
		return 0;

	circuit = rift_csm_state_change(IF_DOWN_FROM_Z,
					circuit_scan_by_ifp(ifp), ifp);
	if (circuit)
		SET_FLAG(circuit->flags, RIFT_CIRCUIT_FLAPPED_AFTER_SPF);

	return 0;
}

static int rift_zebra_if_address_add(int command, struct zclient *zclient,
				     zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;
	struct prefix *p;
	char buf[PREFIX2STR_BUFFER];

	c = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD,
					 zclient->ibuf, vrf_id);

	if (c == NULL)
		return 0;

	p = c->address;

	prefix2str(p, buf, sizeof(buf));
#ifdef EXTREME_DEBUG
	if (p->family == AF_INET)
		zlog_debug("connected IP address %s", buf);
	if (p->family == AF_INET6)
		zlog_debug("connected IPv6 address %s", buf);
#endif /* EXTREME_DEBUG */
	if (if_is_operative(c->ifp))
		rift_circuit_add_addr(circuit_scan_by_ifp(c->ifp), c);

	return 0;
}

static int rift_zebra_if_address_del(int command, struct zclient *client,
				     zebra_size_t length, vrf_id_t vrf_id)
{
	struct connected *c;
	struct interface *ifp;
#ifdef EXTREME_DEBUG
	struct prefix *p;
	char buf[PREFIX2STR_BUFFER];
#endif /* EXTREME_DEBUG */

	c = zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE,
					 zclient->ibuf, vrf_id);

	if (c == NULL)
		return 0;

	ifp = c->ifp;

#ifdef EXTREME_DEBUG
	p = c->address;
	prefix2str(p, buf, sizeof(buf));

	if (p->family == AF_INET)
		zlog_debug("disconnected IP address %s", buf);
	if (p->family == AF_INET6)
		zlog_debug("disconnected IPv6 address %s", buf);
#endif /* EXTREME_DEBUG */

	if (if_is_operative(ifp))
		rift_circuit_del_addr(circuit_scan_by_ifp(ifp), c);
	connected_free(c);

	return 0;
}

static int rift_zebra_link_params(int command, struct zclient *zclient,
				  zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;

	ifp = zebra_interface_link_params_read(zclient->ibuf, vrf_id);

	if (ifp == NULL)
		return 0;

	/* Update TE TLV */
	rift_mpls_te_update(ifp);

	return 0;
}

static void rift_zebra_route_add_route(struct prefix *prefix,
				       struct prefix_ipv6 *src_p,
				       struct rift_route_info *route_info)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct rift_nexthop *nexthop;
	struct rift_nexthop6 *nexthop6;
	struct listnode *node;
	int count = 0;

	if (CHECK_FLAG(route_info->flag, RIFT_ROUTE_FLAG_ZEBRA_SYNCED))
		return;

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = PROTO_TYPE;
	api.safi = SAFI_UNICAST;
	api.prefix = *prefix;
	if (src_p && src_p->prefixlen) {
		api.src_prefix = *src_p;
		SET_FLAG(api.message, ZAPI_MESSAGE_SRCPFX);
	}
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);
	api.metric = route_info->cost;
#if 0
	SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);
	api.distance = route_info->depth;
#endif

	/* Nexthops */
	switch (prefix->family) {
	case AF_INET:
		for (ALL_LIST_ELEMENTS_RO(route_info->nexthops, node,
					  nexthop)) {
			if (count >= MULTIPATH_NUM)
				break;
			api_nh = &api.nexthops[count];
			if (fabricd)
				api_nh->onlink = true;
			api_nh->vrf_id = VRF_DEFAULT;
			/* FIXME: can it be ? */
			if (nexthop->ip.s_addr != INADDR_ANY) {
				api_nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
				api_nh->gate.ipv4 = nexthop->ip;
			} else {
				api_nh->type = NEXTHOP_TYPE_IFINDEX;
			}
			api_nh->ifindex = nexthop->ifindex;
			count++;
		}
		break;
	case AF_INET6:
		for (ALL_LIST_ELEMENTS_RO(route_info->nexthops6, node,
					  nexthop6)) {
			if (count >= MULTIPATH_NUM)
				break;
			if (!IN6_IS_ADDR_LINKLOCAL(&nexthop6->ip6)
			    && !IN6_IS_ADDR_UNSPECIFIED(&nexthop6->ip6)) {
				continue;
			}

			api_nh = &api.nexthops[count];
			if (fabricd)
				api_nh->onlink = true;
			api_nh->vrf_id = VRF_DEFAULT;
			api_nh->gate.ipv6 = nexthop6->ip6;
			api_nh->ifindex = nexthop6->ifindex;
			api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			count++;
		}
		break;
	}
	if (!count)
		return;

	api.nexthop_num = count;

	zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);
	SET_FLAG(route_info->flag, RIFT_ROUTE_FLAG_ZEBRA_SYNCED);
	UNSET_FLAG(route_info->flag, RIFT_ROUTE_FLAG_ZEBRA_RESYNC);
}

static void rift_zebra_route_del_route(struct prefix *prefix,
				       struct prefix_ipv6 *src_p,
				       struct rift_route_info *route_info)
{
	struct zapi_route api;

	if (!CHECK_FLAG(route_info->flag, RIFT_ROUTE_FLAG_ZEBRA_SYNCED))
		return;

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = PROTO_TYPE;
	api.safi = SAFI_UNICAST;
	api.prefix = *prefix;
	if (src_p && src_p->prefixlen) {
		api.src_prefix = *src_p;
		SET_FLAG(api.message, ZAPI_MESSAGE_SRCPFX);
	}

	zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);
	UNSET_FLAG(route_info->flag, RIFT_ROUTE_FLAG_ZEBRA_SYNCED);
}

void rift_zebra_route_update(struct prefix *prefix,
			     struct prefix_ipv6 *src_p,
			     struct rift_route_info *route_info)
{
	if (zclient->sock < 0)
		return;

	if (CHECK_FLAG(route_info->flag, RIFT_ROUTE_FLAG_ACTIVE))
		rift_zebra_route_add_route(prefix, src_p, route_info);
	else
		rift_zebra_route_del_route(prefix, src_p, route_info);
}

static int rift_zebra_read(int command, struct zclient *zclient,
			   zebra_size_t length, vrf_id_t vrf_id)
{
	struct zapi_route api;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;

	if (api.prefix.family == AF_INET6
	    && IN6_IS_ADDR_LINKLOCAL(&api.prefix.u.prefix6))
		return 0;

	/*
	 * Avoid advertising a false default reachability. (A default
	 * route installed by RIFT gets redistributed from zebra back
	 * into RIFT causing us to start advertising default reachabity
	 * without this check)
	 */
	if (api.prefix.prefixlen == 0
	    && api.src_prefix.prefixlen == 0
	    && api.type == PROTO_TYPE) {
		command = ZEBRA_REDISTRIBUTE_ROUTE_DEL;
	}

	if (command == ZEBRA_REDISTRIBUTE_ROUTE_ADD)
		rift_redist_add(api.type, &api.prefix, &api.src_prefix,
				api.distance, api.metric);
	else
		rift_redist_delete(api.type, &api.prefix, &api.src_prefix);

	return 0;
}

int rift_distribute_list_update(int routetype)
{
	return 0;
}

void rift_zebra_redistribute_set(afi_t afi, int type)
{
	if (type == DEFAULT_ROUTE)
		zclient_redistribute_default(ZEBRA_REDISTRIBUTE_DEFAULT_ADD,
					     zclient, afi, VRF_DEFAULT);
	else
		zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient, afi, type,
				     0, VRF_DEFAULT);
}

void rift_zebra_redistribute_unset(afi_t afi, int type)
{
	if (type == DEFAULT_ROUTE)
		zclient_redistribute_default(ZEBRA_REDISTRIBUTE_DEFAULT_DELETE,
					     zclient, afi, VRF_DEFAULT);
	else
		zclient_redistribute(ZEBRA_REDISTRIBUTE_DELETE, zclient, afi,
				     type, 0, VRF_DEFAULT);
}

static void rift_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

void rift_zebra_init(struct thread_master *master)
{
	zclient = zclient_new(master, &zclient_options_default);
	zclient_init(zclient, PROTO_TYPE, 0, &riftd_privs);
	zclient->zebra_connected = rift_zebra_connected;
	zclient->router_id_update = rift_router_id_update_zebra;
	zclient->interface_add = rift_zebra_if_add;
	zclient->interface_delete = rift_zebra_if_del;
	zclient->interface_up = rift_zebra_if_state_up;
	zclient->interface_down = rift_zebra_if_state_down;
	zclient->interface_address_add = rift_zebra_if_address_add;
	zclient->interface_address_delete = rift_zebra_if_address_del;
	zclient->interface_link_params = rift_zebra_link_params;
	zclient->redistribute_route_add = rift_zebra_read;
	zclient->redistribute_route_del = rift_zebra_read;

	return;
}

void rift_zebra_stop(void)
{
	zclient_stop(zclient);
	zclient_free(zclient);
	frr_fini();
}
