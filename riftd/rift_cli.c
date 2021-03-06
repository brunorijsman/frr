/*
 * Copyright (C) 2019        Bruno Rijsman
 *
 * This code is based on the original FRR IS-IS code, which is:
 * 
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 * Copyright (C) 2018        Volta Networks
 *                           Emanuele Di Pascale
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "if.h"
#include "vrf.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "northbound_cli.h"
#include "libfrr.h"
#include "yang.h"
#include "lib/linklist.h"
#include "riftd/riftd.h"
#include "riftd/rift_cli.h"
#include "riftd/rift_misc.h"
#include "riftd/rift_circuit.h"
#include "riftd/rift_csm.h"

#ifndef VTYSH_EXTRACT_PL
#include "riftd/rift_cli_clippy.c"
#endif

/*
 * XPath: /frr-riftd:rift/instance
 */
DEFPY_NOSH(router_rift, router_rift_cmd, "router rift WORD$tag",
	   ROUTER_STR
	   "ISO RIFT\n"
	   "ISO Routing area tag\n")
{
	int ret;
	char base_xpath[XPATH_MAXLEN];

	snprintf(base_xpath, XPATH_MAXLEN,
		 "/frr-riftd:rift/instance[area-tag='%s']", tag);
	nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
	/* default value in yang for is-type is level-1, but in FRR
	 * the first instance is assigned is-type level-1-2. We
	 * need to make sure to set it in the yang model so that it
	 * is consistent with what FRR sees.
	 */
	if (listcount(rift->area_list) == 0)
		nb_cli_enqueue_change(vty, "./is-type", NB_OP_MODIFY,
				      "level-1-2");
	ret = nb_cli_apply_changes(vty, base_xpath);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(RIFT_NODE, base_xpath);

	return ret;
}

DEFPY(no_router_rift, no_router_rift_cmd, "no router rift WORD$tag",
      NO_STR ROUTER_STR
      "ISO RIFT\n"
      "ISO Routing area tag\n")
{
	char temp_xpath[XPATH_MAXLEN];
	struct listnode *node, *nnode;
	struct rift_circuit *circuit = NULL;
	struct rift_area *area = NULL;

	if (!yang_dnode_exists(vty->candidate_config->dnode,
			       "/frr-riftd:rift/instance[area-tag='%s']",
			       tag)) {
		vty_out(vty, "RIFT area %s not found.\n", tag);
		return CMD_ERR_NOTHING_TODO;
	}

	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	area = rift_area_lookup(tag);
	if (area && area->circuit_list && listcount(area->circuit_list)) {
		for (ALL_LIST_ELEMENTS(area->circuit_list, node, nnode,
				       circuit)) {
			/* add callbacks to delete each of the circuits listed
			 */
			const char *vrf_name =
				vrf_lookup_by_id(circuit->interface->vrf_id)
					->name;
			snprintf(
				temp_xpath, XPATH_MAXLEN,
				"/frr-interface:lib/interface[name='%s'][vrf='%s']/frr-riftd:rift",
				circuit->interface->name, vrf_name);
			nb_cli_enqueue_change(vty, temp_xpath, NB_OP_DESTROY,
					      NULL);
		}
	}

	return nb_cli_apply_changes(
		vty, "/frr-riftd:rift/instance[area-tag='%s']", tag);
}

void cli_show_router_rift(struct vty *vty, struct lyd_node *dnode,
			  bool show_defaults)
{
	vty_out(vty, "!\n");
	vty_out(vty, "router rift %s\n",
		yang_dnode_get_string(dnode, "./area-tag"));
}

/*
 * XPath: /frr-interface:lib/interface/frr-riftd:rift/
 * XPath: /frr-interface:lib/interface/frr-riftd:rift/ipv4-routing
 * XPath: /frr-interface:lib/interface/frr-riftd:rift/ipv6-routing
 * XPath: /frr-riftd:rift/instance
 */
DEFPY(ip_router_rift, ip_router_rift_cmd, "ip router rift WORD$tag",
      "Interface Internet Protocol config commands\n"
      "IP router interface commands\n"
      "RIFT routing protocol\n"
      "Routing process tag\n")
{
	char temp_xpath[XPATH_MAXLEN];
	const char *circ_type;
	struct rift_area *area;
	struct interface *ifp;
	const struct lyd_node *dnode =
		yang_dnode_get(running_config->dnode, VTY_CURR_XPATH);

	/* area will be created if it is not present. make sure the yang model
	 * is synced with FRR and call the appropriate NB cb.
	 */
	area = rift_area_lookup(tag);
	if (!area) {
		snprintf(temp_xpath, XPATH_MAXLEN,
			 "/frr-riftd:rift/instance[area-tag='%s']", tag);
		nb_cli_enqueue_change(vty, temp_xpath, NB_OP_CREATE, tag);
		snprintf(temp_xpath, XPATH_MAXLEN,
			 "/frr-riftd:rift/instance[area-tag='%s']/is-type",
			 tag);
		nb_cli_enqueue_change(
			vty, temp_xpath, NB_OP_MODIFY,
			listcount(rift->area_list) == 0 ? "level-1-2" : NULL);
		nb_cli_enqueue_change(vty, "./frr-riftd:rift", NB_OP_CREATE,
				      NULL);
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/area-tag",
				      NB_OP_MODIFY, tag);
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/ipv4-routing",
				      NB_OP_MODIFY, "true");
		nb_cli_enqueue_change(
			vty, "./frr-riftd:rift/circuit-type", NB_OP_MODIFY,
			listcount(rift->area_list) == 0 ? "level-1-2"
							: "level-1");
	} else {
		/* area exists, circuit type defaults to its area's is_type */
		switch (area->is_type) {
		case IS_LEVEL_1:
			circ_type = "level-1";
			break;
		case IS_LEVEL_2:
			circ_type = "level-2";
			break;
		case IS_LEVEL_1_AND_2:
			circ_type = "level-1-2";
			break;
		default:
			/* just to silence compiler warnings */
			return CMD_WARNING_CONFIG_FAILED;
		}
		nb_cli_enqueue_change(vty, "./frr-riftd:rift", NB_OP_CREATE,
				      NULL);
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/area-tag",
				      NB_OP_MODIFY, tag);
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/ipv4-routing",
				      NB_OP_MODIFY, "true");
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/circuit-type",
				      NB_OP_MODIFY, circ_type);
	}

	/* check if the interface is a loopback and if so set it as passive */
	ifp = yang_dnode_get_entry(dnode, false);
	if (ifp && if_is_loopback(ifp))
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/passive",
				      NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(ip6_router_rift, ip6_router_rift_cmd, "ipv6 router rift WORD$tag",
      "Interface Internet Protocol config commands\n"
      "IP router interface commands\n"
      "RIFT routing protocol\n"
      "Routing process tag\n")
{
	char temp_xpath[XPATH_MAXLEN];
	const char *circ_type;
	struct rift_area *area;
	struct interface *ifp;
	const struct lyd_node *dnode =
		yang_dnode_get(running_config->dnode, VTY_CURR_XPATH);

	/* area will be created if it is not present. make sure the yang model
	 * is synced with FRR and call the appropriate NB cb.
	 */
	area = rift_area_lookup(tag);
	if (!area) {
		snprintf(temp_xpath, XPATH_MAXLEN,
			 "/frr-riftd:rift/instance[area-tag='%s']", tag);
		nb_cli_enqueue_change(vty, temp_xpath, NB_OP_CREATE, tag);
		snprintf(temp_xpath, XPATH_MAXLEN,
			 "/frr-riftd:rift/instance[area-tag='%s']/is-type",
			 tag);
		nb_cli_enqueue_change(
			vty, temp_xpath, NB_OP_MODIFY,
			listcount(rift->area_list) == 0 ? "level-1-2" : NULL);
		nb_cli_enqueue_change(vty, "./frr-riftd:rift", NB_OP_CREATE,
				      NULL);
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/area-tag",
				      NB_OP_MODIFY, tag);
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/ipv6-routing",
				      NB_OP_MODIFY, "true");
		nb_cli_enqueue_change(
			vty, "./frr-riftd:rift/circuit-type", NB_OP_MODIFY,
			listcount(rift->area_list) == 0 ? "level-1-2"
							: "level-1");
	} else {
		/* area exists, circuit type defaults to its area's is_type */
		switch (area->is_type) {
		case IS_LEVEL_1:
			circ_type = "level-1";
			break;
		case IS_LEVEL_2:
			circ_type = "level-2";
			break;
		case IS_LEVEL_1_AND_2:
			circ_type = "level-1-2";
			break;
		default:
			/* just to silence compiler warnings */
			return CMD_WARNING_CONFIG_FAILED;
		}
		nb_cli_enqueue_change(vty, "./frr-riftd:rift", NB_OP_CREATE,
				      NULL);
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/area-tag",
				      NB_OP_MODIFY, tag);
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/ipv6-routing",
				      NB_OP_MODIFY, "true");
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/circuit-type",
				      NB_OP_MODIFY, circ_type);
	}

	/* check if the interface is a loopback and if so set it as passive */
	ifp = yang_dnode_get_entry(dnode, false);
	if (ifp && if_is_loopback(ifp))
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/passive",
				      NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_ip_router_rift, no_ip_router_rift_cmd,
      "no <ip|ipv6>$ip router rift [WORD]$tag",
      NO_STR
      "Interface Internet Protocol config commands\n"
      "IP router interface commands\n"
      "IP router interface commands\n"
      "RIFT routing protocol\n"
      "Routing process tag\n")
{
	const struct lyd_node *dnode;

	dnode = yang_dnode_get(vty->candidate_config->dnode,
			       "%s/frr-riftd:rift", VTY_CURR_XPATH);
	if (!dnode)
		return CMD_SUCCESS;

	/*
	 * If both ipv4 and ipv6 are off delete the interface rift container.
	 */
	if (strmatch(ip, "ipv6")) {
		if (!yang_dnode_get_bool(dnode, "./ipv4-routing"))
			nb_cli_enqueue_change(vty, "./frr-riftd:rift",
					      NB_OP_DESTROY, NULL);
		else
			nb_cli_enqueue_change(vty,
					      "./frr-riftd:rift/ipv6-routing",
					      NB_OP_MODIFY, "false");
	} else {
		if (!yang_dnode_get_bool(dnode, "./ipv6-routing"))
			nb_cli_enqueue_change(vty, "./frr-riftd:rift",
					      NB_OP_DESTROY, NULL);
		else
			nb_cli_enqueue_change(vty,
					      "./frr-riftd:rift/ipv4-routing",
					      NB_OP_MODIFY, "false");
	}

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_rift_ipv4(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " ip router rift %s\n",
		yang_dnode_get_string(dnode, "../area-tag"));
}

void cli_show_ip_rift_ipv6(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " ipv6 router rift %s\n",
		yang_dnode_get_string(dnode, "../area-tag"));
}

/* TODO: Come up with new CLI commands for RIFT (that don't conflict with any other protocol) */

/*
 * XPath: /frr-riftd:rift/instance/area-address
 */
DEFPY(rift_net, rift_net_cmd, "[no] net WORD",
      "Remove an existing Network Entity Title for this process\n"
      "A Network Entity Title for this process (OSI only)\n"
      "XX.XXXX. ... .XXX.XX  Network entity title (NET)\n")
{
	nb_cli_enqueue_change(vty, "./area-address",
			      no ? NB_OP_DESTROY : NB_OP_CREATE, net);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_area_address(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults)
{
	vty_out(vty, " net %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-riftd:rift/instance/is-type
 */
DEFPY(rift_is_type, rift_is_type_cmd, "is-type <level-1|level-1-2|level-2-only>$level",
      "IS Level for this routing process (OSI only)\n"
      "Act as a station router only\n"
      "Act as both a station router and an area router\n"
      "Act as an area router only\n")
{
	nb_cli_enqueue_change(vty, "./is-type", NB_OP_MODIFY,
			      strmatch(level, "level-2-only") ? "level-2"
							      : level);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_rift_is_type, no_rift_is_type_cmd,
      "no is-type [<level-1|level-1-2|level-2-only>]",
      NO_STR
      "IS Level for this routing process (OSI only)\n"
      "Act as a station router only\n"
      "Act as both a station router and an area router\n"
      "Act as an area router only\n")
{
	const char *value = NULL;
	const struct lyd_node *dnode =
		yang_dnode_get(running_config->dnode, VTY_CURR_XPATH);
	struct rift_area *area = yang_dnode_get_entry(dnode, false);

	/*
	 * Put the is-type back to defaults:
	 * - level-1-2 on first area
	 * - level-1 for the rest
	 */
	if (area && listgetdata(listhead(rift->area_list)) == area)
		value = "level-1-2";
	else
		value = NULL;
	nb_cli_enqueue_change(vty, "./is-type", NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_is_type(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults)
{
	int is_type = yang_dnode_get_enum(dnode, NULL);

	switch (is_type) {
	case IS_LEVEL_1:
		vty_out(vty, " is-type level-1\n");
		break;
	case IS_LEVEL_2:
		vty_out(vty, " is-type level-2-only\n");
		break;
	case IS_LEVEL_1_AND_2:
		vty_out(vty, " is-type level-1-2\n");
		break;
	}
}

/*
 * XPath: /frr-riftd:rift/instance/dynamic-hostname
 */
DEFPY(rift_dynamic_hostname, rift_dynamic_hostname_cmd, "[no] hostname dynamic",
      NO_STR
      "Dynamic hostname for RIFT\n"
      "Dynamic hostname\n")
{
	nb_cli_enqueue_change(vty, "./dynamic-hostname", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_dynamic_hostname(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " hostname dynamic\n");
}

/*
 * XPath: /frr-riftd:rift/instance/overload
 */
DEFPY(rift_set_overload_bit, rift_set_overload_bit_cmd, "[no] set-overload-bit",
      "Reset overload bit to accept transit traffic\n"
      "Set overload bit to avoid any transit traffic\n")
{
	nb_cli_enqueue_change(vty, "./overload", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_overload(struct vty *vty, struct lyd_node *dnode,
			    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " set-overload-bit\n");
}

/*
 * XPath: /frr-riftd:rift/instance/attached
 */
DEFPY(rift_set_attached_bit, rift_set_attached_bit_cmd, "[no] set-attached-bit",
      "Reset attached bit\n"
      "Set attached bit to identify as L1/L2 router for inter-area traffic\n")
{
	nb_cli_enqueue_change(vty, "./attached", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_attached(struct vty *vty, struct lyd_node *dnode,
			    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " set-attached-bit\n");
}

/*
 * XPath: /frr-riftd:rift/instance/metric-style
 */
DEFPY(rift_metric_style, rift_metric_style_cmd,
      "metric-style <narrow|transition|wide>$style",
      "Use old-style (ISO 10589) or new-style packet formats\n"
      "Use old style of TLVs with narrow metric\n"
      "Send and accept both styles of TLVs during transition\n"
      "Use new style of TLVs to carry wider metric\n")
{
	nb_cli_enqueue_change(vty, "./metric-style", NB_OP_MODIFY, style);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_rift_metric_style, no_rift_metric_style_cmd,
      "no metric-style [narrow|transition|wide]",
      NO_STR
      "Use old-style (ISO 10589) or new-style packet formats\n"
      "Use old style of TLVs with narrow metric\n"
      "Send and accept both styles of TLVs during transition\n"
      "Use new style of TLVs to carry wider metric\n")
{
	nb_cli_enqueue_change(vty, "./metric-style", NB_OP_MODIFY, "narrow");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_metric_style(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults)
{
	int metric = yang_dnode_get_enum(dnode, NULL);

	switch (metric) {
	case RIFT_NARROW_METRIC:
		vty_out(vty, " metric-style narrow\n");
		break;
	case RIFT_WIDE_METRIC:
		vty_out(vty, " metric-style wide\n");
		break;
	case RIFT_TRANSITION_METRIC:
		vty_out(vty, " metric-style transition\n");
		break;
	}
}

/*
 * XPath: /frr-riftd:rift/instance/area-password
 */
DEFPY(rift_area_passwd, rift_area_passwd_cmd,
      "area-password <clear|md5>$pwd_type WORD$pwd [authenticate snp <send-only|validate>$snp]",
      "Configure the authentication password for an area\n"
      "Clear-text authentication type\n"
      "MD5 authentication type\n"
      "Level-wide password\n"
      "Authentication\n"
      "SNP PDUs\n"
      "Send but do not check PDUs on receiving\n"
      "Send and check PDUs on receiving\n")
{
	nb_cli_enqueue_change(vty, "./area-password", NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./area-password/password", NB_OP_MODIFY,
			      pwd);
	nb_cli_enqueue_change(vty, "./area-password/password-type",
			      NB_OP_MODIFY, pwd_type);
	nb_cli_enqueue_change(vty, "./area-password/authenticate-snp",
			      NB_OP_MODIFY, snp ? snp : "none");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_area_pwd(struct vty *vty, struct lyd_node *dnode,
			    bool show_defaults)
{
	const char *snp;

	vty_out(vty, " area-password %s %s",
		yang_dnode_get_string(dnode, "./password-type"),
		yang_dnode_get_string(dnode, "./password"));
	snp = yang_dnode_get_string(dnode, "./authenticate-snp");
	if (!strmatch("none", snp))
		vty_out(vty, " authenticate snp %s", snp);
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-riftd:rift/instance/domain-password
 */
DEFPY(rift_domain_passwd, rift_domain_passwd_cmd,
      "domain-password <clear|md5>$pwd_type WORD$pwd [authenticate snp <send-only|validate>$snp]",
      "Set the authentication password for a routing domain\n"
      "Clear-text authentication type\n"
      "MD5 authentication type\n"
      "Level-wide password\n"
      "Authentication\n"
      "SNP PDUs\n"
      "Send but do not check PDUs on receiving\n"
      "Send and check PDUs on receiving\n")
{
	nb_cli_enqueue_change(vty, "./domain-password", NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./domain-password/password", NB_OP_MODIFY,
			      pwd);
	nb_cli_enqueue_change(vty, "./domain-password/password-type",
			      NB_OP_MODIFY, pwd_type);
	nb_cli_enqueue_change(vty, "./domain-password/authenticate-snp",
			      NB_OP_MODIFY, snp ? snp : "none");

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_rift_area_passwd, no_rift_area_passwd_cmd,
      "no <area-password|domain-password>$cmd",
      NO_STR
      "Configure the authentication password for an area\n"
      "Set the authentication password for a routing domain\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, "./%s", cmd);
}

void cli_show_rift_domain_pwd(struct vty *vty, struct lyd_node *dnode,
			      bool show_defaults)
{
	const char *snp;

	vty_out(vty, " domain-password %s %s",
		yang_dnode_get_string(dnode, "./password-type"),
		yang_dnode_get_string(dnode, "./password"));
	snp = yang_dnode_get_string(dnode, "./authenticate-snp");
	if (!strmatch("none", snp))
		vty_out(vty, " authenticate snp %s", snp);
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-riftd:rift/instance/lsp/generation-interval
 */
DEFPY(rift_lsp_gen_interval, rift_lsp_gen_interval_cmd,
      "lsp-gen-interval [level-1|level-2]$level (1-120)$val",
      "Minimum interval between regenerating same LSP\n"
      "Set interval for level 1 only\n"
      "Set interval for level 2 only\n"
      "Minimum interval in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./lsp/generation-interval/level-1",
				      NB_OP_MODIFY, val_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./lsp/generation-interval/level-2",
				      NB_OP_MODIFY, val_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_rift_lsp_gen_interval, no_rift_lsp_gen_interval_cmd,
      "no lsp-gen-interval [level-1|level-2]$level [(1-120)]",
      NO_STR
      "Minimum interval between regenerating same LSP\n"
      "Set interval for level 1 only\n"
      "Set interval for level 2 only\n"
      "Minimum interval in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./lsp/generation-interval/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./lsp/generation-interval/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_lsp_gen_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "./level-1");
	const char *l2 = yang_dnode_get_string(dnode, "./level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " lsp-gen-interval %s\n", l1);
	else {
		vty_out(vty, " lsp-gen-interval level-1 %s\n", l1);
		vty_out(vty, " lsp-gen-interval level-2 %s\n", l2);
	}
}

/*
 * XPath: /frr-riftd:rift/instance/lsp/refresh-interval
 */
DEFPY(rift_lsp_refresh_interval, rift_lsp_refresh_interval_cmd,
      "lsp-refresh-interval [level-1|level-2]$level (1-65235)$val",
      "LSP refresh interval\n"
      "LSP refresh interval for Level 1 only\n"
      "LSP refresh interval for Level 2 only\n"
      "LSP refresh interval in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./lsp/refresh-interval/level-1",
				      NB_OP_MODIFY, val_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./lsp/refresh-interval/level-2",
				      NB_OP_MODIFY, val_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_rift_lsp_refresh_interval, no_rift_lsp_refresh_interval_cmd,
      "no lsp-refresh-interval [level-1|level-2]$level [(1-65235)]",
      NO_STR
      "LSP refresh interval\n"
      "LSP refresh interval for Level 1 only\n"
      "LSP refresh interval for Level 2 only\n"
      "LSP refresh interval in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./lsp/refresh-interval/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./lsp/refresh-interval/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_lsp_ref_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "./level-1");
	const char *l2 = yang_dnode_get_string(dnode, "./level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " lsp-refresh-interval %s\n", l1);
	else {
		vty_out(vty, " lsp-refresh-interval level-1 %s\n", l1);
		vty_out(vty, " lsp-refresh-interval level-2 %s\n", l2);
	}
}

/*
 * XPath: /frr-riftd:rift/instance/lsp/maximum-lifetime
 */
DEFPY(rift_max_lsp_lifetime, rift_max_lsp_lifetime_cmd,
      "max-lsp-lifetime [level-1|level-2]$level (350-65535)$val",
      "Maximum LSP lifetime\n"
      "Maximum LSP lifetime for Level 1 only\n"
      "Maximum LSP lifetime for Level 2 only\n"
      "LSP lifetime in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./lsp/maximum-lifetime/level-1",
				      NB_OP_MODIFY, val_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./lsp/maximum-lifetime/level-2",
				      NB_OP_MODIFY, val_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_rift_max_lsp_lifetime, no_rift_max_lsp_lifetime_cmd,
      "no max-lsp-lifetime [level-1|level-2]$level [(350-65535)]",
      NO_STR
      "Maximum LSP lifetime\n"
      "Maximum LSP lifetime for Level 1 only\n"
      "Maximum LSP lifetime for Level 2 only\n"
      "LSP lifetime in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./lsp/maximum-lifetime/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./lsp/maximum-lifetime/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_lsp_max_lifetime(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "./level-1");
	const char *l2 = yang_dnode_get_string(dnode, "./level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " max-lsp-lifetime %s\n", l1);
	else {
		vty_out(vty, " max-lsp-lifetime level-1 %s\n", l1);
		vty_out(vty, " max-lsp-lifetime level-2 %s\n", l2);
	}
}

/*
 * XPath: /frr-riftd:rift/instance/lsp/mtu
 */
DEFPY(rift_area_lsp_mtu, rift_area_lsp_mtu_cmd, "lsp-mtu (128-4352)$val",
      "Configure the maximum size of generated LSPs\n"
      "Maximum size of generated LSPs\n")
{
	nb_cli_enqueue_change(vty, "./lsp/mtu", NB_OP_MODIFY, val_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_rift_area_lsp_mtu, no_rift_area_lsp_mtu_cmd, "no lsp-mtu [(128-4352)]",
      NO_STR
      "Configure the maximum size of generated LSPs\n"
      "Maximum size of generated LSPs\n")
{
	nb_cli_enqueue_change(vty, "./lsp/mtu", NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_lsp_mtu(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults)
{
	vty_out(vty, " lsp-mtu %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * XPath: /frr-riftd:rift/instance/spf/minimum-interval
 */
DEFPY(rift_spf_interval, rift_spf_interval_cmd,
      "spf-interval [level-1|level-2]$level (1-120)$val",
      "Minimum interval between SPF calculations\n"
      "Set interval for level 1 only\n"
      "Set interval for level 2 only\n"
      "Minimum interval between consecutive SPFs in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./spf/minimum-interval/level-1",
				      NB_OP_MODIFY, val_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./spf/minimum-interval/level-2",
				      NB_OP_MODIFY, val_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_rift_spf_interval, no_rift_spf_interval_cmd,
      "no spf-interval [level-1|level-2]$level [(1-120)]",
      NO_STR
      "Minimum interval between SPF calculations\n"
      "Set interval for level 1 only\n"
      "Set interval for level 2 only\n"
      "Minimum interval between consecutive SPFs in seconds\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./spf/minimum-interval/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./spf/minimum-interval/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_spf_min_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "./level-1");
	const char *l2 = yang_dnode_get_string(dnode, "./level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " spf-interval %s\n", l1);
	else {
		vty_out(vty, " spf-interval level-1 %s\n", l1);
		vty_out(vty, " spf-interval level-2 %s\n", l2);
	}
}

/*
 * XPath: /frr-riftd:rift/instance/spf/ietf-backoff-delay
 */
DEFPY(rift_spf_delay_ietf, rift_spf_delay_ietf_cmd,
      "spf-delay-ietf init-delay (0-60000) short-delay (0-60000) long-delay (0-60000) holddown (0-60000) time-to-learn (0-60000)",
      "IETF SPF delay algorithm\n"
      "Delay used while in QUIET state\n"
      "Delay used while in QUIET state in milliseconds\n"
      "Delay used while in SHORT_WAIT state\n"
      "Delay used while in SHORT_WAIT state in milliseconds\n"
      "Delay used while in LONG_WAIT\n"
      "Delay used while in LONG_WAIT state in milliseconds\n"
      "Time with no received IGP events before considering IGP stable\n"
      "Time with no received IGP events before considering IGP stable (in milliseconds)\n"
      "Maximum duration needed to learn all the events related to a single failure\n"
      "Maximum duration needed to learn all the events related to a single failure (in milliseconds)\n")
{
	nb_cli_enqueue_change(vty, "./spf/ietf-backoff-delay", NB_OP_CREATE,
			      NULL);
	nb_cli_enqueue_change(vty, "./spf/ietf-backoff-delay/init-delay",
			      NB_OP_MODIFY, init_delay_str);
	nb_cli_enqueue_change(vty, "./spf/ietf-backoff-delay/short-delay",
			      NB_OP_MODIFY, short_delay_str);
	nb_cli_enqueue_change(vty, "./spf/ietf-backoff-delay/long-delay",
			      NB_OP_MODIFY, long_delay_str);
	nb_cli_enqueue_change(vty, "./spf/ietf-backoff-delay/hold-down",
			      NB_OP_MODIFY, holddown_str);
	nb_cli_enqueue_change(vty, "./spf/ietf-backoff-delay/time-to-learn",
			      NB_OP_MODIFY, time_to_learn_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_rift_spf_delay_ietf, no_rift_spf_delay_ietf_cmd,
      "no spf-delay-ietf [init-delay (0-60000) short-delay (0-60000) long-delay (0-60000) holddown (0-60000) time-to-learn (0-60000)]",
      NO_STR
      "IETF SPF delay algorithm\n"
      "Delay used while in QUIET state\n"
      "Delay used while in QUIET state in milliseconds\n"
      "Delay used while in SHORT_WAIT state\n"
      "Delay used while in SHORT_WAIT state in milliseconds\n"
      "Delay used while in LONG_WAIT\n"
      "Delay used while in LONG_WAIT state in milliseconds\n"
      "Time with no received IGP events before considering IGP stable\n"
      "Time with no received IGP events before considering IGP stable (in milliseconds)\n"
      "Maximum duration needed to learn all the events related to a single failure\n"
      "Maximum duration needed to learn all the events related to a single failure (in milliseconds)\n")
{
	nb_cli_enqueue_change(vty, "./spf/ietf-backoff-delay", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_spf_ietf_backoff(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults)
{
	vty_out(vty,
		" spf-delay-ietf init-delay %s short-delay %s long-delay %s holddown %s time-to-learn %s\n",
		yang_dnode_get_string(dnode, "./init-delay"),
		yang_dnode_get_string(dnode, "./short-delay"),
		yang_dnode_get_string(dnode, "./long-delay"),
		yang_dnode_get_string(dnode, "./hold-down"),
		yang_dnode_get_string(dnode, "./time-to-learn"));
}

/*
 * XPath: /frr-riftd:rift/instance/purge-originator
 */
DEFPY(rift_area_purge_originator, rift_area_purge_originator_cmd, "[no] purge-originator",
      NO_STR "Use the RFC 6232 purge-originator\n")
{
	nb_cli_enqueue_change(vty, "./purge-originator", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_purge_origin(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " purge-originator\n");
}

/*
 * XPath: /frr-riftd:rift/mpls-te
 */
DEFPY(rift_mpls_te_on, rift_mpls_te_on_cmd, "mpls-te on",
      MPLS_TE_STR "Enable the MPLS-TE functionality\n")
{
	nb_cli_enqueue_change(vty, "/frr-riftd:rift/mpls-te", NB_OP_CREATE,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_rift_mpls_te_on, no_rift_mpls_te_on_cmd, "no mpls-te [on]",
      NO_STR
      "Disable the MPLS-TE functionality\n"
      "Enable the MPLS-TE functionality\n")
{
	nb_cli_enqueue_change(vty, "/frr-riftd:rift/mpls-te", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_mpls_te(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults)
{
	vty_out(vty, "  mpls-te on\n");
}

/*
 * XPath: /frr-riftd:rift/mpls-te/router-address
 */
DEFPY(rift_mpls_te_router_addr, rift_mpls_te_router_addr_cmd,
      "mpls-te router-address A.B.C.D",
      MPLS_TE_STR
      "Stable IP address of the advertising router\n"
      "MPLS-TE router address in IPv4 address format\n")
{
	nb_cli_enqueue_change(vty, "/frr-riftd:rift/mpls-te/router-address",
			      NB_OP_MODIFY, router_address_str);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_mpls_te_router_addr(struct vty *vty, struct lyd_node *dnode,
				       bool show_defaults)
{
	vty_out(vty, "  mpls-te router-address %s\n",
		yang_dnode_get_string(dnode, NULL));
}

DEFPY(rift_mpls_te_inter_as, rift_mpls_te_inter_as_cmd,
      "[no] mpls-te inter-as [level-1|level-1-2|level-2-only]",
      NO_STR MPLS_TE_STR
      "Configure MPLS-TE Inter-AS support\n"
      "AREA native mode self originate INTER-AS LSP with L1 only flooding scope\n"
      "AREA native mode self originate INTER-AS LSP with L1 and L2 flooding scope\n"
      "AS native mode self originate INTER-AS LSP with L2 only flooding scope\n")
{
	vty_out(vty, "MPLS-TE Inter-AS is not yet supported.");
	return CMD_SUCCESS;
}

/*
 * XPath: /frr-riftd:rift/instance/default-information-originate
 */
DEFPY(rift_default_originate, rift_default_originate_cmd,
      "[no] default-information originate <ipv4|ipv6>$ip"
      " <level-1|level-2>$level [always]$always"
      " [<metric (0-16777215)$metric|route-map WORD$rmap>]",
      NO_STR
      "Control distribution of default information\n"
      "Distribute a default route\n"
      "Distribute default route for IPv4\n"
      "Distribute default route for IPv6\n"
      "Distribute default route into level-1\n"
      "Distribute default route into level-2\n"
      "Always advertise default route\n"
      "Metric for default route\n"
      "RIFT default metric\n"
      "Route map reference\n"
      "Pointer to route-map entries\n")
{
	if (no)
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./always", NB_OP_MODIFY,
				      always ? "true" : "false");
		nb_cli_enqueue_change(vty, "./route-map",
				      rmap ? NB_OP_MODIFY : NB_OP_DESTROY,
				      rmap ? rmap : NULL);
		nb_cli_enqueue_change(vty, "./metric",
				      metric ? NB_OP_MODIFY : NB_OP_DESTROY,
				      metric ? metric_str : NULL);
		if (strmatch(ip, "ipv6") && !always) {
			vty_out(vty,
				"Zebra doesn't implement default-originate for IPv6 yet\n");
			vty_out(vty,
				"so use with care or use default-originate always.\n");
		}
	}

	return nb_cli_apply_changes(
		vty, "./default-information-originate/%s[level='%s']", ip,
		level);
}

static void vty_print_def_origin(struct vty *vty, struct lyd_node *dnode,
				 const char *family, const char *level,
				 bool show_defaults)
{
	const char *metric;

	vty_out(vty, " default-information originate %s %s", family, level);
	if (yang_dnode_get_bool(dnode, "./always"))
		vty_out(vty, " always");

	if (yang_dnode_exists(dnode, "./route-map"))
		vty_out(vty, " route-map %s",
			yang_dnode_get_string(dnode, "./route-map"));
	else if (yang_dnode_exists(dnode, "./metric")) {
		metric = yang_dnode_get_string(dnode, "./metric");
		if (show_defaults || !yang_dnode_is_default(dnode, "./metric"))
			vty_out(vty, " metric %s", metric);
	}
	vty_out(vty, "\n");
}

void cli_show_rift_def_origin_ipv4(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults)
{
	const char *level = yang_dnode_get_string(dnode, "./level");

	vty_print_def_origin(vty, dnode, "ipv4", level, show_defaults);
}

void cli_show_rift_def_origin_ipv6(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults)
{
	const char *level = yang_dnode_get_string(dnode, "./level");

	vty_print_def_origin(vty, dnode, "ipv6", level, show_defaults);
}

/*
 * XPath: /frr-riftd:rift/instance/redistribute
 */
DEFPY(rift_redistribute, rift_redistribute_cmd,
      "[no] redistribute <ipv4|ipv6>$ip " PROTO_REDIST_STR
      "$proto"
      " <level-1|level-2>$level"
      " [<metric (0-16777215)|route-map WORD>]",
      NO_STR REDIST_STR
      "Redistribute IPv4 routes\n"
      "Redistribute IPv6 routes\n" PROTO_REDIST_HELP
      "Redistribute into level-1\n"
      "Redistribute into level-2\n"
      "Metric for redistributed routes\n"
      "RIFT default metric\n"
      "Route map reference\n"
      "Pointer to route-map entries\n")
{
	if (no)
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./route-map",
				      route_map ? NB_OP_MODIFY : NB_OP_DESTROY,
				      route_map ? route_map : NULL);
		nb_cli_enqueue_change(vty, "./metric",
				      metric ? NB_OP_MODIFY : NB_OP_DESTROY,
				      metric ? metric_str : NULL);
	}

	return nb_cli_apply_changes(
		vty, "./redistribute/%s[protocol='%s'][level='%s']", ip, proto,
		level);
}

static void vty_print_redistribute(struct vty *vty, struct lyd_node *dnode,
				   const char *family)
{
	const char *level = yang_dnode_get_string(dnode, "./level");
	const char *protocol = yang_dnode_get_string(dnode, "./protocol");

	vty_out(vty, " redistribute %s %s %s", family, protocol, level);
	if (yang_dnode_exists(dnode, "./metric"))
		vty_out(vty, " metric %s",
			yang_dnode_get_string(dnode, "./metric"));
	else if (yang_dnode_exists(dnode, "./route-map"))
		vty_out(vty, " route-map %s",
			yang_dnode_get_string(dnode, "./route-map"));
	vty_out(vty, "\n");
}

void cli_show_rift_redistribute_ipv4(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults)
{
	vty_print_redistribute(vty, dnode, "ipv4");
}
void cli_show_rift_redistribute_ipv6(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults)
{
	vty_print_redistribute(vty, dnode, "ipv6");
}

/*
 * XPath: /frr-riftd:rift/instance/multi-topology
 */
DEFPY(rift_topology, rift_topology_cmd,
      "[no] topology "
      "<ipv4-unicast"
      "|ipv4-mgmt"
      "|ipv6-unicast"
      "|ipv4-multicast"
      "|ipv6-multicast"
      "|ipv6-mgmt"
      "|ipv6-dstsrc>$topology "
      "[overload]$overload",
      NO_STR
      "Configure RIFT topologies\n"
      "IPv4 unicast topology\n"
      "IPv4 management topology\n"
      "IPv6 unicast topology\n"
      "IPv4 multicast topology\n"
      "IPv6 multicast topology\n"
      "IPv6 management topology\n"
      "IPv6 dst-src topology\n"
      "Set overload bit for topology\n")
{
	char base_xpath[XPATH_MAXLEN];

	/* Since IPv4-unicast is not configurable it is not present in the
	 * YANG model, so we need to validate it here
	 */
	if (strmatch(topology, "ipv4-unicast")) {
		vty_out(vty, "Cannot configure IPv4 unicast topology\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (strmatch(topology, "ipv4-mgmt"))
		snprintf(base_xpath, XPATH_MAXLEN,
			 "./multi-topology/ipv4-management");
	else if (strmatch(topology, "ipv6-mgmt"))
		snprintf(base_xpath, XPATH_MAXLEN,
			 "./multi-topology/ipv6-management");
	else
		snprintf(base_xpath, XPATH_MAXLEN, "./multi-topology/%s",
			 topology);

	if (no)
		nb_cli_enqueue_change(vty, ".", NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, ".", NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, "./overload", NB_OP_MODIFY,
				      overload ? "true" : "false");
	}

	return nb_cli_apply_changes(vty, base_xpath);
}

void cli_show_rift_mt_ipv4_multicast(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults)
{
	vty_out(vty, " topology ipv4-multicast");
	if (yang_dnode_get_bool(dnode, "./overload"))
		vty_out(vty, " overload");
	vty_out(vty, "\n");
}

void cli_show_rift_mt_ipv4_mgmt(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults)
{
	vty_out(vty, " topology ipv4-mgmt");
	if (yang_dnode_get_bool(dnode, "./overload"))
		vty_out(vty, " overload");
	vty_out(vty, "\n");
}

void cli_show_rift_mt_ipv6_unicast(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults)
{
	vty_out(vty, " topology ipv6-unicast");
	if (yang_dnode_get_bool(dnode, "./overload"))
		vty_out(vty, " overload");
	vty_out(vty, "\n");
}

void cli_show_rift_mt_ipv6_multicast(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults)
{
	vty_out(vty, " topology ipv6-multicast");
	if (yang_dnode_get_bool(dnode, "./overload"))
		vty_out(vty, " overload");
	vty_out(vty, "\n");
}

void cli_show_rift_mt_ipv6_mgmt(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults)
{
	vty_out(vty, " topology ipv6-mgmt");
	if (yang_dnode_get_bool(dnode, "./overload"))
		vty_out(vty, " overload");
	vty_out(vty, "\n");
}

void cli_show_rift_mt_ipv6_dstsrc(struct vty *vty, struct lyd_node *dnode,
				  bool show_defaults)
{
	vty_out(vty, " topology ipv6-dstsrc");
	if (yang_dnode_get_bool(dnode, "./overload"))
		vty_out(vty, " overload");
	vty_out(vty, "\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-riftd:rift/passive
 */
DEFPY(rift_passive, rift_passive_cmd, "[no] rift passive",
      NO_STR
      "RIFT routing protocol\n"
      "Configure the passive mode for interface\n")
{
	nb_cli_enqueue_change(vty, "./frr-riftd:rift/passive", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_rift_passive(struct vty *vty, struct lyd_node *dnode,
			      bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " rift passive\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-riftd:rift/password
 */

DEFPY(rift_passwd, rift_passwd_cmd, "rift password <md5|clear>$type WORD$pwd",
      "RIFT routing protocol\n"
      "Configure the authentication password for a circuit\n"
      "HMAC-MD5 authentication\n"
      "Cleartext password\n"
      "Circuit password\n")
{
	nb_cli_enqueue_change(vty, "./frr-riftd:rift/password", NB_OP_CREATE,
			      NULL);
	nb_cli_enqueue_change(vty, "./frr-riftd:rift/password/password",
			      NB_OP_MODIFY, pwd);
	nb_cli_enqueue_change(vty, "./frr-riftd:rift/password/password-type",
			      NB_OP_MODIFY, type);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_rift_passwd, no_rift_passwd_cmd, "no rift password [<md5|clear> WORD]",
      NO_STR
      "RIFT routing protocol\n"
      "Configure the authentication password for a circuit\n"
      "HMAC-MD5 authentication\n"
      "Cleartext password\n"
      "Circuit password\n")
{
	nb_cli_enqueue_change(vty, "./frr-riftd:rift/password", NB_OP_DESTROY,
			      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_rift_password(struct vty *vty, struct lyd_node *dnode,
			       bool show_defaults)
{
	vty_out(vty, " rift password %s %s\n",
		yang_dnode_get_string(dnode, "./password-type"),
		yang_dnode_get_string(dnode, "./password"));
}

/*
 * XPath: /frr-interface:lib/interface/frr-riftd:rift/metric
 */
DEFPY(rift_metric, rift_metric_cmd,
      "rift metric [level-1|level-2]$level (0-16777215)$met",
      "RIFT routing protocol\n"
      "Set default metric for circuit\n"
      "Specify metric for level-1 routing\n"
      "Specify metric for level-2 routing\n"
      "Default metric value\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/metric/level-1",
				      NB_OP_MODIFY, met_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/metric/level-2",
				      NB_OP_MODIFY, met_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_rift_metric, no_rift_metric_cmd,
      "no rift metric [level-1|level-2]$level [(0-16777215)]",
      NO_STR
      "RIFT routing protocol\n"
      "Set default metric for circuit\n"
      "Specify metric for level-1 routing\n"
      "Specify metric for level-2 routing\n"
      "Default metric value\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/metric/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/metric/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_rift_metric(struct vty *vty, struct lyd_node *dnode,
			     bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "./level-1");
	const char *l2 = yang_dnode_get_string(dnode, "./level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " rift metric %s\n", l1);
	else {
		vty_out(vty, " rift metric %s level-1\n", l1);
		vty_out(vty, " rift metric %s level-2\n", l2);
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-riftd:rift/hello/interval
 */
DEFPY(rift_hello_interval, rift_hello_interval_cmd,
      "rift hello-interval [level-1|level-2]$level (1-600)$intv",
      "RIFT routing protocol\n"
      "Set Hello interval\n"
      "Specify hello-interval for level-1 IIHs\n"
      "Specify hello-interval for level-2 IIHs\n"
      "Holdtime 1 seconds, interval depends on multiplier\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty,
				      "./frr-riftd:rift/hello/interval/level-1",
				      NB_OP_MODIFY, intv_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty,
				      "./frr-riftd:rift/hello/interval/level-2",
				      NB_OP_MODIFY, intv_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_rift_hello_interval, no_rift_hello_interval_cmd,
      "no rift hello-interval [level-1|level-2]$level [(1-600)]",
      NO_STR
      "RIFT routing protocol\n"
      "Set Hello interval\n"
      "Specify hello-interval for level-1 IIHs\n"
      "Specify hello-interval for level-2 IIHs\n"
      "Holdtime 1 second, interval depends on multiplier\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty,
				      "./frr-riftd:rift/hello/interval/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty,
				      "./frr-riftd:rift/hello/interval/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_rift_hello_interval(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "./level-1");
	const char *l2 = yang_dnode_get_string(dnode, "./level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " rift hello-interval %s\n", l1);
	else {
		vty_out(vty, " rift hello-interval %s level-1\n", l1);
		vty_out(vty, " rift hello-interval %s level-2\n", l2);
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-riftd:rift/hello/multiplier
 */
DEFPY(rift_hello_multiplier, rift_hello_multiplier_cmd,
      "rift hello-multiplier [level-1|level-2]$level (2-100)$mult",
      "RIFT routing protocol\n"
      "Set multiplier for Hello holding time\n"
      "Specify hello multiplier for level-1 IIHs\n"
      "Specify hello multiplier for level-2 IIHs\n"
      "Hello multiplier value\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(
			vty, "./frr-riftd:rift/hello/multiplier/level-1",
			NB_OP_MODIFY, mult_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(
			vty, "./frr-riftd:rift/hello/multiplier/level-2",
			NB_OP_MODIFY, mult_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_rift_hello_multiplier, no_rift_hello_multiplier_cmd,
      "no rift hello-multiplier [level-1|level-2]$level [(2-100)]",
      NO_STR
      "RIFT routing protocol\n"
      "Set multiplier for Hello holding time\n"
      "Specify hello multiplier for level-1 IIHs\n"
      "Specify hello multiplier for level-2 IIHs\n"
      "Hello multiplier value\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(
			vty, "./frr-riftd:rift/hello/multiplier/level-1",
			NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(
			vty, "./frr-riftd:rift/hello/multiplier/level-2",
			NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_rift_hello_multi(struct vty *vty, struct lyd_node *dnode,
				  bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "./level-1");
	const char *l2 = yang_dnode_get_string(dnode, "./level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " rift hello-multiplier %s\n", l1);
	else {
		vty_out(vty, " rift hello-multiplier %s level-1\n", l1);
		vty_out(vty, " rift hello-multiplier %s level-2\n", l2);
	}
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-riftd:rift/disable-three-way-handshake
 */
DEFPY(rift_threeway_adj, rift_threeway_adj_cmd, "[no] rift three-way-handshake",
      NO_STR
      "RIFT commands\n"
      "Enable/Disable three-way handshake\n")
{
	nb_cli_enqueue_change(vty,
			      "./frr-riftd:rift/disable-three-way-handshake",
			      NB_OP_MODIFY, no ? "true" : "false");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_rift_threeway_shake(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " rift three-way-handshake\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-riftd:rift/hello/padding
 */
DEFPY(rift_hello_padding, rift_hello_padding_cmd, "[no] rift hello padding",
      NO_STR
      "RIFT routing protocol\n"
      "Add padding to RIFT hello packets\n"
      "Pad hello packets\n")
{
	nb_cli_enqueue_change(vty, "./frr-riftd:rift/hello/padding",
			      NB_OP_MODIFY, no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_rift_hello_padding(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");

	vty_out(vty, " rift hello padding\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-riftd:rift/csnp-interval
 */
DEFPY(csnp_interval, rift_csnp_interval_cmd,
      "rift csnp-interval (1-600)$intv [level-1|level-2]$level",
      "RIFT routing protocol\n"
      "Set CSNP interval in seconds\n"
      "CSNP interval value\n"
      "Specify interval for level-1 CSNPs\n"
      "Specify interval for level-2 CSNPs\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty,
				      "./frr-riftd:rift/csnp-interval/level-1",
				      NB_OP_MODIFY, intv_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty,
				      "./frr-riftd:rift/csnp-interval/level-2",
				      NB_OP_MODIFY, intv_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_csnp_interval, no_rift_csnp_interval_cmd,
      "no rift csnp-interval [(1-600)] [level-1|level-2]$level",
      NO_STR
      "RIFT routing protocol\n"
      "Set CSNP interval in seconds\n"
      "CSNP interval value\n"
      "Specify interval for level-1 CSNPs\n"
      "Specify interval for level-2 CSNPs\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty,
				      "./frr-riftd:rift/csnp-interval/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty,
				      "./frr-riftd:rift/csnp-interval/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_rift_csnp_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "./level-1");
	const char *l2 = yang_dnode_get_string(dnode, "./level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " rift csnp-interval %s\n", l1);
	else {
		vty_out(vty, " rift csnp-interval %s level-1\n", l1);
		vty_out(vty, " rift csnp-interval %s level-2\n", l2);
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-riftd:rift/psnp-interval
 */
DEFPY(psnp_interval, rift_psnp_interval_cmd,
      "rift psnp-interval (1-120)$intv [level-1|level-2]$level",
      "RIFT routing protocol\n"
      "Set PSNP interval in seconds\n"
      "PSNP interval value\n"
      "Specify interval for level-1 PSNPs\n"
      "Specify interval for level-2 PSNPs\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty,
				      "./frr-riftd:rift/psnp-interval/level-1",
				      NB_OP_MODIFY, intv_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty,
				      "./frr-riftd:rift/psnp-interval/level-2",
				      NB_OP_MODIFY, intv_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_psnp_interval, no_rift_psnp_interval_cmd,
      "no rift psnp-interval [(1-120)] [level-1|level-2]$level",
      NO_STR
      "RIFT routing protocol\n"
      "Set PSNP interval in seconds\n"
      "PSNP interval value\n"
      "Specify interval for level-1 PSNPs\n"
      "Specify interval for level-2 PSNPs\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty,
				      "./frr-riftd:rift/psnp-interval/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty,
				      "./frr-riftd:rift/psnp-interval/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_rift_psnp_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "./level-1");
	const char *l2 = yang_dnode_get_string(dnode, "./level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " rift psnp-interval %s\n", l1);
	else {
		vty_out(vty, " rift psnp-interval %s level-1\n", l1);
		vty_out(vty, " rift psnp-interval %s level-2\n", l2);
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-riftd:rift/multi-topology
 */
DEFPY(circuit_topology, rift_circuit_topology_cmd,
      "[no] rift topology"
      "<ipv4-unicast"
      "|ipv4-mgmt"
      "|ipv6-unicast"
      "|ipv4-multicast"
      "|ipv6-multicast"
      "|ipv6-mgmt"
      "|ipv6-dstsrc"
      ">$topology",
      NO_STR
      "RIFT routing protocol\n"
      "Configure interface RIFT topologies\n"
      "IPv4 unicast topology\n"
      "IPv4 management topology\n"
      "IPv6 unicast topology\n"
      "IPv4 multicast topology\n"
      "IPv6 multicast topology\n"
      "IPv6 management topology\n"
      "IPv6 dst-src topology\n")
{
	nb_cli_enqueue_change(vty, ".", NB_OP_MODIFY, no ? "false" : "true");

	if (strmatch(topology, "ipv4-mgmt"))
		return nb_cli_apply_changes(
			vty, "./frr-riftd:rift/multi-topology/ipv4-management");
	else if (strmatch(topology, "ipv6-mgmt"))
		return nb_cli_apply_changes(
			vty, "./frr-riftd:rift/multi-topology/ipv6-management");
	else
		return nb_cli_apply_changes(
			vty, "./frr-riftd:rift/multi-topology/%s", topology);
}

void cli_show_ip_rift_mt_ipv4_unicast(struct vty *vty, struct lyd_node *dnode,
				      bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " rift topology ipv4-unicast\n");
}

void cli_show_ip_rift_mt_ipv4_multicast(struct vty *vty, struct lyd_node *dnode,
					bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " rift topology ipv4-multicast\n");
}

void cli_show_ip_rift_mt_ipv4_mgmt(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " rift topology ipv4-mgmt\n");
}

void cli_show_ip_rift_mt_ipv6_unicast(struct vty *vty, struct lyd_node *dnode,
				      bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " rift topology ipv6-unicast\n");
}

void cli_show_ip_rift_mt_ipv6_multicast(struct vty *vty, struct lyd_node *dnode,
					bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " rift topology ipv6-multicast\n");
}

void cli_show_ip_rift_mt_ipv6_mgmt(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " rift topology ipv6-mgmt\n");
}

void cli_show_ip_rift_mt_ipv6_dstsrc(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " rift topology ipv6-dstsrc\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-riftd:rift/circuit-type
 */
DEFPY(rift_circuit_type, rift_circuit_type_cmd,
      "rift circuit-type <level-1|level-1-2|level-2-only>$type",
      "RIFT routing protocol\n"
      "Configure circuit type for interface\n"
      "Level-1 only adjacencies are formed\n"
      "Level-1-2 adjacencies are formed\n"
      "Level-2 only adjacencies are formed\n")
{
	nb_cli_enqueue_change(
		vty, "./frr-riftd:rift/circuit-type", NB_OP_MODIFY,
		strmatch(type, "level-2-only") ? "level-2" : type);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_rift_circuit_type, no_rift_circuit_type_cmd,
      "no rift circuit-type [level-1|level-1-2|level-2-only]",
      NO_STR
      "RIFT routing protocol\n"
      "Configure circuit type for interface\n"
      "Level-1 only adjacencies are formed\n"
      "Level-1-2 adjacencies are formed\n"
      "Level-2 only adjacencies are formed\n")
{
	const struct lyd_node *dnode;
	struct interface *ifp;
	struct rift_circuit *circuit;
	int is_type;
	const char *circ_type;

	/*
	 * Default value depends on whether the circuit is part of an area,
	 * and the is-type of the area if there is one. So we need to do this
	 * here.
	 */
	dnode = yang_dnode_get(running_config->dnode, VTY_CURR_XPATH);
	ifp = yang_dnode_get_entry(dnode, false);
	if (!ifp)
		goto def_val;

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit)
		goto def_val;

	if (circuit->state == C_STATE_UP)
		is_type = circuit->area->is_type;
	else
		goto def_val;

	switch (is_type) {
	case IS_LEVEL_1:
		circ_type = "level-1";
		break;
	case IS_LEVEL_2:
		circ_type = "level-2";
		break;
	case IS_LEVEL_1_AND_2:
		circ_type = "level-1-2";
		break;
	default:
		return CMD_ERR_NO_MATCH;
	}
	nb_cli_enqueue_change(vty, "./frr-riftd:rift/circuit-type",
			      NB_OP_MODIFY, circ_type);

	return nb_cli_apply_changes(vty, NULL);

def_val:
	nb_cli_enqueue_change(vty, "./frr-riftd:rift/circuit-type",
			      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_rift_circ_type(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults)
{
	int level = yang_dnode_get_enum(dnode, NULL);

	switch (level) {
	case IS_LEVEL_1:
		vty_out(vty, " rift circuit-type level-1\n");
		break;
	case IS_LEVEL_2:
		vty_out(vty, " rift circuit-type level-2-only\n");
		break;
	case IS_LEVEL_1_AND_2:
		vty_out(vty, " rift circuit-type level-1-2\n");
		break;
	}
}

/*
 * XPath: /frr-interface:lib/interface/frr-riftd:rift/network-type
 */
DEFPY(rift_network, rift_network_cmd, "[no] rift network point-to-point",
      NO_STR
      "RIFT routing protocol\n"
      "Set network type\n"
      "point-to-point network type\n")
{
	nb_cli_enqueue_change(vty, "./frr-riftd:rift/network-type",
			      NB_OP_MODIFY,
			      no ? "broadcast" : "point-to-point");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_rift_network_type(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults)
{
	if (yang_dnode_get_enum(dnode, NULL) != CIRCUIT_T_P2P)
		vty_out(vty, " no");

	vty_out(vty, " rift network point-to-point\n");
}

/*
 * XPath: /frr-interface:lib/interface/frr-riftd:rift/priority
 */
DEFPY(rift_priority, rift_priority_cmd,
      "rift priority (0-127)$prio [level-1|level-2]$level",
      "RIFT routing protocol\n"
      "Set priority for Designated Router election\n"
      "Priority value\n"
      "Specify priority for level-1 routing\n"
      "Specify priority for level-2 routing\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/priority/level-1",
				      NB_OP_MODIFY, prio_str);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/priority/level-2",
				      NB_OP_MODIFY, prio_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY(no_rift_priority, no_rift_priority_cmd,
      "no rift priority [(0-127)] [level-1|level-2]$level",
      NO_STR
      "RIFT routing protocol\n"
      "Set priority for Designated Router election\n"
      "Priority value\n"
      "Specify priority for level-1 routing\n"
      "Specify priority for level-2 routing\n")
{
	if (!level || strmatch(level, "level-1"))
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/priority/level-1",
				      NB_OP_MODIFY, NULL);
	if (!level || strmatch(level, "level-2"))
		nb_cli_enqueue_change(vty, "./frr-riftd:rift/priority/level-2",
				      NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_ip_rift_priority(struct vty *vty, struct lyd_node *dnode,
			       bool show_defaults)
{
	const char *l1 = yang_dnode_get_string(dnode, "./level-1");
	const char *l2 = yang_dnode_get_string(dnode, "./level-2");

	if (strmatch(l1, l2))
		vty_out(vty, " rift priority %s\n", l1);
	else {
		vty_out(vty, " rift priority %s level-1\n", l1);
		vty_out(vty, " rift priority %s level-2\n", l2);
	}
}

/*
 * XPath: /frr-riftd:rift/instance/log-adjacency-changes
 */
DEFPY(log_adj_changes, rift_log_adj_changes_cmd, "[no] log-adjacency-changes",
      NO_STR "Log changes in adjacency state\n")
{
	nb_cli_enqueue_change(vty, "./log-adjacency-changes", NB_OP_MODIFY,
			      no ? "false" : "true");

	return nb_cli_apply_changes(vty, NULL);
}

void cli_show_rift_log_adjacency(struct vty *vty, struct lyd_node *dnode,
				 bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no");
	vty_out(vty, " log-adjacency-changes\n");
}

void rift_cli_init(void)
{
	install_element(CONFIG_NODE, &router_rift_cmd);
	install_element(CONFIG_NODE, &no_router_rift_cmd);

	install_element(INTERFACE_NODE, &ip_router_rift_cmd);
	install_element(INTERFACE_NODE, &ip6_router_rift_cmd);
	install_element(INTERFACE_NODE, &no_ip_router_rift_cmd);

	install_element(RIFT_NODE, &rift_net_cmd);

	install_element(RIFT_NODE, &rift_is_type_cmd);
	install_element(RIFT_NODE, &no_rift_is_type_cmd);

	install_element(RIFT_NODE, &rift_dynamic_hostname_cmd);

	install_element(RIFT_NODE, &rift_set_overload_bit_cmd);
	install_element(RIFT_NODE, &rift_set_attached_bit_cmd);

	install_element(RIFT_NODE, &rift_metric_style_cmd);
	install_element(RIFT_NODE, &no_rift_metric_style_cmd);

	install_element(RIFT_NODE, &rift_area_passwd_cmd);
	install_element(RIFT_NODE, &rift_domain_passwd_cmd);
	install_element(RIFT_NODE, &no_rift_area_passwd_cmd);

	install_element(RIFT_NODE, &rift_lsp_gen_interval_cmd);
	install_element(RIFT_NODE, &no_rift_lsp_gen_interval_cmd);
	install_element(RIFT_NODE, &rift_lsp_refresh_interval_cmd);
	install_element(RIFT_NODE, &no_rift_lsp_refresh_interval_cmd);
	install_element(RIFT_NODE, &rift_max_lsp_lifetime_cmd);
	install_element(RIFT_NODE, &no_rift_max_lsp_lifetime_cmd);
	install_element(RIFT_NODE, &rift_area_lsp_mtu_cmd);
	install_element(RIFT_NODE, &no_rift_area_lsp_mtu_cmd);

	install_element(RIFT_NODE, &rift_spf_interval_cmd);
	install_element(RIFT_NODE, &no_rift_spf_interval_cmd);
	install_element(RIFT_NODE, &rift_spf_delay_ietf_cmd);
	install_element(RIFT_NODE, &no_rift_spf_delay_ietf_cmd);

	install_element(RIFT_NODE, &rift_area_purge_originator_cmd);

	install_element(RIFT_NODE, &rift_mpls_te_on_cmd);
	install_element(RIFT_NODE, &no_rift_mpls_te_on_cmd);
	install_element(RIFT_NODE, &rift_mpls_te_router_addr_cmd);
	install_element(RIFT_NODE, &rift_mpls_te_inter_as_cmd);

	install_element(RIFT_NODE, &rift_default_originate_cmd);
	install_element(RIFT_NODE, &rift_redistribute_cmd);

	install_element(RIFT_NODE, &rift_topology_cmd);

	install_element(INTERFACE_NODE, &rift_passive_cmd);

	install_element(INTERFACE_NODE, &rift_passwd_cmd);
	install_element(INTERFACE_NODE, &no_rift_passwd_cmd);

	install_element(INTERFACE_NODE, &rift_metric_cmd);
	install_element(INTERFACE_NODE, &no_rift_metric_cmd);

	install_element(INTERFACE_NODE, &rift_hello_interval_cmd);
	install_element(INTERFACE_NODE, &no_rift_hello_interval_cmd);

	install_element(INTERFACE_NODE, &rift_hello_multiplier_cmd);
	install_element(INTERFACE_NODE, &no_rift_hello_multiplier_cmd);

	install_element(INTERFACE_NODE, &rift_threeway_adj_cmd);

	install_element(INTERFACE_NODE, &rift_hello_padding_cmd);

	install_element(INTERFACE_NODE, &rift_csnp_interval_cmd);
	install_element(INTERFACE_NODE, &no_rift_csnp_interval_cmd);

	install_element(INTERFACE_NODE, &rift_psnp_interval_cmd);
	install_element(INTERFACE_NODE, &no_rift_psnp_interval_cmd);

	install_element(INTERFACE_NODE, &rift_circuit_topology_cmd);

	install_element(INTERFACE_NODE, &rift_circuit_type_cmd);
	install_element(INTERFACE_NODE, &no_rift_circuit_type_cmd);

	install_element(INTERFACE_NODE, &rift_network_cmd);

	install_element(INTERFACE_NODE, &rift_priority_cmd);
	install_element(INTERFACE_NODE, &no_rift_priority_cmd);

	install_element(RIFT_NODE, &rift_log_adj_changes_cmd);
}
