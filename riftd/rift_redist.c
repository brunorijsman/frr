/*
 * RIFT Rout(e)ing protocol - rift_redist.c
 *
 * Copyright (C) 2019 Bruno Rijsman
 *
 * This code is based on the original FRR IS-IS code, which is:
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

#include <zebra.h>

#include "command.h"
#include "if.h"
#include "linklist.h"
#include "memory.h"
#include "rift_memory.h"
#include "prefix.h"
#include "routemap.h"
#include "stream.h"
#include "table.h"
#include "vty.h"
#include "srcdest_table.h"

#include "riftd/dict.h"
#include "riftd/rift_constants.h"
#include "riftd/rift_common.h"
#include "riftd/rift_flags.h"
#include "riftd/rift_misc.h"
#include "riftd/rift_circuit.h"
#include "riftd/riftd.h"
#include "riftd/rift_lsp.h"
#include "riftd/rift_route.h"
#include "riftd/rift_zebra.h"

static int redist_protocol(int family)
{
	if (family == AF_INET)
		return 0;
	if (family == AF_INET6)
		return 1;

	assert(!"Unsupported address family!");
	return 0;
}

static afi_t afi_for_redist_protocol(int protocol)
{
	if (protocol == 0)
		return AFI_IP;
	if (protocol == 1)
		return AFI_IP6;

	assert(!"Unknown redist protocol!");
	return AFI_IP;
}

static struct route_table *get_ext_info(struct rift *i, int family)
{
	int protocol = redist_protocol(family);

	return i->ext_info[protocol];
}

static struct rift_redist *get_redist_settings(struct rift_area *area,
					       int family, int type, int level)
{
	int protocol = redist_protocol(family);

	return &area->redist_settings[protocol][type][level - 1];
}

struct route_table *get_ext_reach(struct rift_area *area, int family, int level)
{
	int protocol = redist_protocol(family);

	return area->ext_reach[protocol][level - 1];
}

/* Install external reachability information into a
 * specific area for a specific level.
 * Schedule an lsp regenerate if necessary */
static void rift_redist_install(struct rift_area *area, int level,
				const struct prefix *p,
				const struct prefix_ipv6 *src_p,
				struct rift_ext_info *info)
{
	int family = p->family;
	struct route_table *er_table = get_ext_reach(area, family, level);
	struct route_node *er_node;

	if (!er_table) {
		zlog_warn(
			"%s: External reachability table of area %s"
			" is not initialized.",
			__func__, area->area_tag);
		return;
	}

	er_node = srcdest_rnode_get(er_table, p, src_p);
	if (er_node->info) {
		route_unlock_node(er_node);

		/* Don't update/reschedule lsp generation if nothing changed. */
		if (!memcmp(er_node->info, info, sizeof(*info)))
			return;
	} else {
		er_node->info = XMALLOC(MTYPE_RIFT_EXT_INFO, sizeof(*info));
	}

	memcpy(er_node->info, info, sizeof(*info));
	lsp_regenerate_schedule(area, level, 0);
}

/* Remove external reachability information from a
 * specific area for a specific level.
 * Schedule an lsp regenerate if necessary. */
static void rift_redist_uninstall(struct rift_area *area, int level,
				  const struct prefix *p,
				  const struct prefix_ipv6 *src_p)
{
	int family = p->family;
	struct route_table *er_table = get_ext_reach(area, family, level);
	struct route_node *er_node;

	if (!er_table) {
		zlog_warn(
			"%s: External reachability table of area %s"
			" is not initialized.",
			__func__, area->area_tag);
		return;
	}

	er_node = srcdest_rnode_lookup(er_table, p, src_p);
	if (!er_node)
		return;
	else
		route_unlock_node(er_node);

	if (!er_node->info)
		return;

	XFREE(MTYPE_RIFT_EXT_INFO, er_node->info);
	route_unlock_node(er_node);
	lsp_regenerate_schedule(area, level, 0);
}

/* Update external reachability info of area for a given level
 * and prefix, using the given redistribution settings. */
static void rift_redist_update_ext_reach(struct rift_area *area, int level,
					 struct rift_redist *redist,
					 const struct prefix *p,
					 const struct prefix_ipv6 *src_p,
					 struct rift_ext_info *info)
{
	struct rift_ext_info area_info;
	route_map_result_t map_ret;

	memcpy(&area_info, info, sizeof(area_info));
	area_info.metric = redist->metric;

	if (redist->map_name) {
		map_ret =
			route_map_apply(redist->map, p, RMAP_RIFT, &area_info);
		if (map_ret == RMAP_DENYMATCH)
			area_info.distance = 255;
	}

	/* Allow synthesized default routes only on always orignate */
	if (area_info.origin == DEFAULT_ROUTE
	    && redist->redist != DEFAULT_ORIGINATE_ALWAYS)
		area_info.distance = 255;

	if (area_info.distance < 255)
		rift_redist_install(area, level, p, src_p, &area_info);
	else
		rift_redist_uninstall(area, level, p, src_p);
}

static void rift_redist_ensure_default(struct rift *rift, int family)
{
	struct prefix p;
	struct route_table *ei_table = get_ext_info(rift, family);
	struct route_node *ei_node;
	struct rift_ext_info *info;

	if (family == AF_INET) {
		p.family = AF_INET;
		p.prefixlen = 0;
		memset(&p.u.prefix4, 0, sizeof(p.u.prefix4));
	} else if (family == AF_INET6) {
		p.family = AF_INET6;
		p.prefixlen = 0;
		memset(&p.u.prefix6, 0, sizeof(p.u.prefix6));
	} else
		assert(!"Unknown family!");

	ei_node = srcdest_rnode_get(ei_table, &p, NULL);
	if (ei_node->info) {
		route_unlock_node(ei_node);
		return;
	}

	ei_node->info =
		XCALLOC(MTYPE_RIFT_EXT_INFO, sizeof(struct rift_ext_info));

	info = ei_node->info;
	info->origin = DEFAULT_ROUTE;
	info->distance = 254;
	info->metric = MAX_WIDE_PATH_METRIC;
}

/* Handle notification about route being added */
void rift_redist_add(int type, struct prefix *p, struct prefix_ipv6 *src_p,
		     uint8_t distance, uint32_t metric)
{
	int family = p->family;
	struct route_table *ei_table = get_ext_info(rift, family);
	struct route_node *ei_node;
	struct rift_ext_info *info;
	struct listnode *node;
	struct rift_area *area;
	int level;
	struct rift_redist *redist;

	char debug_buf[BUFSIZ];
	prefix2str(p, debug_buf, sizeof(debug_buf));

	zlog_debug("%s: New route %s from %s: distance %d.", __func__,
		   debug_buf, zebra_route_string(type), distance);

	if (!ei_table) {
		zlog_warn("%s: External information table not initialized.",
			  __func__);
		return;
	}

	ei_node = srcdest_rnode_get(ei_table, p, src_p);
	if (ei_node->info)
		route_unlock_node(ei_node);
	else
		ei_node->info = XCALLOC(MTYPE_RIFT_EXT_INFO,
					sizeof(struct rift_ext_info));

	info = ei_node->info;
	info->origin = type;
	info->distance = distance;
	info->metric = metric;

	if (is_default_prefix(p)
	    && (!src_p || !src_p->prefixlen)) {
		type = DEFAULT_ROUTE;
	}

	for (ALL_LIST_ELEMENTS_RO(rift->area_list, node, area))
		for (level = 1; level <= RIFT_LEVELS; level++) {
			redist = get_redist_settings(area, family, type, level);
			if (!redist->redist)
				continue;

			rift_redist_update_ext_reach(area, level, redist, p,
						     src_p, info);
		}
}

void rift_redist_delete(int type, struct prefix *p, struct prefix_ipv6 *src_p)
{
	int family = p->family;
	struct route_table *ei_table = get_ext_info(rift, family);
	struct route_node *ei_node;
	struct listnode *node;
	struct rift_area *area;
	int level;
	struct rift_redist *redist;

	char debug_buf[BUFSIZ];
	prefix2str(p, debug_buf, sizeof(debug_buf));

	zlog_debug("%s: Removing route %s from %s.", __func__, debug_buf,
		   zebra_route_string(type));

	if (is_default_prefix(p)
	    && (!src_p || !src_p->prefixlen)) {
		/* Don't remove default route but add synthetic route for use
		 * by "default-information originate always". Areas without the
		 * "always" setting will ignore routes with origin
		 * DEFAULT_ROUTE. */
		rift_redist_add(DEFAULT_ROUTE, p, NULL,
				254, MAX_WIDE_PATH_METRIC);
		return;
	}

	if (!ei_table) {
		zlog_warn("%s: External information table not initialized.",
			  __func__);
		return;
	}

	ei_node = srcdest_rnode_lookup(ei_table, p, src_p);
	if (!ei_node || !ei_node->info) {
		char buf[BUFSIZ];
		prefix2str(p, buf, sizeof(buf));
		zlog_warn(
			"%s: Got a delete for %s route %s, but that route"
			" was never added.",
			__func__, zebra_route_string(type), buf);
		if (ei_node)
			route_unlock_node(ei_node);
		return;
	}
	route_unlock_node(ei_node);

	for (ALL_LIST_ELEMENTS_RO(rift->area_list, node, area))
		for (level = RIFT_LEVEL1; level <= RIFT_LEVEL2; level++) {
			redist = get_redist_settings(area, family, type, level);
			if (!redist->redist)
				continue;

			rift_redist_uninstall(area, level, p, src_p);
		}

	XFREE(MTYPE_RIFT_EXT_INFO, ei_node->info);
	route_unlock_node(ei_node);
}

static void rift_redist_routemap_set(struct rift_redist *redist,
				     const char *routemap)
{
	if (redist->map_name) {
		XFREE(MTYPE_RIFT, redist->map_name);
		route_map_counter_decrement(redist->map);
		redist->map = NULL;
	}

	if (routemap && strlen(routemap)) {
		redist->map_name = XSTRDUP(MTYPE_RIFT, routemap);
		redist->map = route_map_lookup_by_name(routemap);
		route_map_counter_increment(redist->map);
	}
}

static void rift_redist_update_zebra_subscriptions(struct rift *rift)
{
	struct listnode *node;
	struct rift_area *area;
	int type;
	int level;
	int protocol;

	char do_subscribe[REDIST_PROTOCOL_COUNT][ZEBRA_ROUTE_MAX + 1];

	memset(do_subscribe, 0, sizeof(do_subscribe));

	for (ALL_LIST_ELEMENTS_RO(rift->area_list, node, area))
		for (protocol = 0; protocol < REDIST_PROTOCOL_COUNT; protocol++)
			for (type = 0; type < ZEBRA_ROUTE_MAX + 1; type++)
				for (level = 0; level < RIFT_LEVELS; level++)
					if (area->redist_settings[protocol]
								 [type]
								 [level].redist)
						do_subscribe[protocol][type] =
							1;

	for (protocol = 0; protocol < REDIST_PROTOCOL_COUNT; protocol++)
		for (type = 0; type < ZEBRA_ROUTE_MAX + 1; type++) {
			/* This field is actually controlling transmission of
			 * the RIFT
			 * routes to Zebra and has nothing to do with
			 * redistribution,
			 * so skip it. */
			if (type == PROTO_TYPE)
				continue;

			afi_t afi = afi_for_redist_protocol(protocol);

			if (do_subscribe[protocol][type])
				rift_zebra_redistribute_set(afi, type);
			else
				rift_zebra_redistribute_unset(afi, type);
		}
}

void rift_redist_set(struct rift_area *area, int level, int family, int type,
		     uint32_t metric, const char *routemap, int originate_type)
{
	int protocol = redist_protocol(family);
	struct rift_redist *redist =
		get_redist_settings(area, family, type, level);
	int i;
	struct route_table *ei_table;
	struct route_node *rn;
	struct rift_ext_info *info;

	redist->redist = (type == DEFAULT_ROUTE) ? originate_type : 1;
	redist->metric = metric;
	rift_redist_routemap_set(redist, routemap);

	if (!area->ext_reach[protocol][level - 1]) {
		area->ext_reach[protocol][level - 1] = srcdest_table_init();
	}

	for (i = 0; i < REDIST_PROTOCOL_COUNT; i++) {
		if (!area->rift->ext_info[i]) {
			area->rift->ext_info[i] = srcdest_table_init();
		}
	}

	rift_redist_update_zebra_subscriptions(area->rift);

	if (type == DEFAULT_ROUTE && originate_type == DEFAULT_ORIGINATE_ALWAYS)
		rift_redist_ensure_default(area->rift, family);

	ei_table = get_ext_info(area->rift, family);
	for (rn = route_top(ei_table); rn; rn = srcdest_route_next(rn)) {
		if (!rn->info)
			continue;
		info = rn->info;

		const struct prefix *p, *src_p;

		srcdest_rnode_prefixes(rn, &p, &src_p);

		if (type == DEFAULT_ROUTE) {
			if (!is_default_prefix(p)
			    || (src_p && src_p->prefixlen)) {
				continue;
			}
		} else {
			if (info->origin != type)
				continue;
		}

		rift_redist_update_ext_reach(area, level, redist, p,
					     (const struct prefix_ipv6 *)src_p,
					     info);
	}
}

void rift_redist_unset(struct rift_area *area, int level, int family, int type)
{
	struct rift_redist *redist =
		get_redist_settings(area, family, type, level);
	struct route_table *er_table = get_ext_reach(area, family, level);
	struct route_node *rn;
	struct rift_ext_info *info;

	if (!redist->redist)
		return;

	redist->redist = 0;
	if (!er_table) {
		zlog_warn("%s: External reachability table uninitialized.",
			  __func__);
		return;
	}

	for (rn = route_top(er_table); rn; rn = srcdest_route_next(rn)) {
		if (!rn->info)
			continue;
		info = rn->info;

		const struct prefix *p, *src_p;
		srcdest_rnode_prefixes(rn, &p, &src_p);

		if (type == DEFAULT_ROUTE) {
			if (!is_default_prefix(p)
			    || (src_p && src_p->prefixlen)) {
				continue;
			}
		} else {
			if (info->origin != type)
				continue;
		}

		XFREE(MTYPE_RIFT_EXT_INFO, rn->info);
		route_unlock_node(rn);
	}

	lsp_regenerate_schedule(area, level, 0);
	rift_redist_update_zebra_subscriptions(area->rift);
}

void rift_redist_area_finish(struct rift_area *area)
{
	int protocol;
	int level;
	int type;

	for (protocol = 0; protocol < REDIST_PROTOCOL_COUNT; protocol++)
		for (level = 0; level < RIFT_LEVELS; level++) {
			for (type = 0; type < ZEBRA_ROUTE_MAX + 1; type++) {
				struct rift_redist *redist;

				redist = &area->redist_settings[protocol][type]
							       [level];
				redist->redist = 0;
				XFREE(MTYPE_RIFT, redist->map_name);
			}
			route_table_finish(area->ext_reach[protocol][level]);
		}

	rift_redist_update_zebra_subscriptions(area->rift);
}

int rift_redist_config_write(struct vty *vty, struct rift_area *area,
			     int family)
{
	int type;
	int level;
	int write = 0;
	struct rift_redist *redist;
	const char *family_str;

	if (family == AF_INET)
		family_str = "ipv4";
	else if (family == AF_INET6)
		family_str = "ipv6";
	else
		return 0;

	for (type = 0; type < ZEBRA_ROUTE_MAX; type++) {
		if (type == PROTO_TYPE)
			continue;

		for (level = 1; level <= RIFT_LEVELS; level++) {
			redist = get_redist_settings(area, family, type, level);
			if (!redist->redist)
				continue;
			vty_out(vty, " redistribute %s %s", family_str,
				zebra_route_string(type));
			if (!fabricd)
				vty_out(vty, " level-%d", level);
			if (redist->metric)
				vty_out(vty, " metric %u", redist->metric);
			if (redist->map_name)
				vty_out(vty, " route-map %s", redist->map_name);
			vty_out(vty, "\n");
			write++;
		}
	}

	for (level = 1; level <= RIFT_LEVELS; level++) {
		redist =
			get_redist_settings(area, family, DEFAULT_ROUTE, level);
		if (!redist->redist)
			continue;
		vty_out(vty, " default-information originate %s",
			family_str);
		if (!fabricd)
			vty_out(vty, " level-%d", level);
		if (redist->redist == DEFAULT_ORIGINATE_ALWAYS)
			vty_out(vty, " always");
		if (redist->metric)
			vty_out(vty, " metric %u", redist->metric);
		if (redist->map_name)
			vty_out(vty, " route-map %s", redist->map_name);
		vty_out(vty, "\n");
		write++;
	}

	return write;
}

void rift_redist_init(void)
{
}
