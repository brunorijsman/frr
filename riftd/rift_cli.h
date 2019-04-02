/*
 * Copyright (C) 2018       Volta Networks
 *                          Emanuele Di Pascale
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

#ifndef RIFTD_RIFT_CLI_H_
#define RIFTD_RIFT_CLI_H_

/* add cli_show declarations here as externs */
void cli_show_router_rift(struct vty *vty, struct lyd_node *dnode,
			  bool show_defaults);
void cli_show_ip_rift_ipv4(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_ip_rift_ipv6(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_rift_area_address(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_rift_is_type(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_rift_dynamic_hostname(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_rift_attached(struct vty *vty, struct lyd_node *dnode,
			    bool show_defaults);
void cli_show_rift_overload(struct vty *vty, struct lyd_node *dnode,
			    bool show_defaults);
void cli_show_rift_metric_style(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_rift_area_pwd(struct vty *vty, struct lyd_node *dnode,
			    bool show_defaults);
void cli_show_rift_domain_pwd(struct vty *vty, struct lyd_node *dnode,
			      bool show_defaults);
void cli_show_rift_lsp_gen_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_rift_lsp_ref_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_rift_lsp_max_lifetime(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_rift_lsp_mtu(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_rift_spf_min_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_rift_spf_ietf_backoff(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_rift_purge_origin(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_rift_mpls_te(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults);
void cli_show_rift_mpls_te_router_addr(struct vty *vty, struct lyd_node *dnode,
				       bool show_defaults);
void cli_show_rift_def_origin_ipv4(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_rift_def_origin_ipv6(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_rift_redistribute_ipv4(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_rift_redistribute_ipv6(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_rift_mt_ipv4_multicast(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_rift_mt_ipv4_mgmt(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_rift_mt_ipv6_unicast(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_rift_mt_ipv6_multicast(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_rift_mt_ipv6_mgmt(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_rift_mt_ipv6_dstsrc(struct vty *vty, struct lyd_node *dnode,
				  bool show_defaults);
void cli_show_ip_rift_passive(struct vty *vty, struct lyd_node *dnode,
			      bool show_defaults);
void cli_show_ip_rift_password(struct vty *vty, struct lyd_node *dnode,
			       bool show_defaults);
void cli_show_ip_rift_metric(struct vty *vty, struct lyd_node *dnode,
			     bool show_defaults);
void cli_show_ip_rift_hello_interval(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_ip_rift_hello_multi(struct vty *vty, struct lyd_node *dnode,
				  bool show_defaults);
void cli_show_ip_rift_threeway_shake(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_ip_rift_hello_padding(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_ip_rift_csnp_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_ip_rift_psnp_interval(struct vty *vty, struct lyd_node *dnode,
				    bool show_defaults);
void cli_show_ip_rift_mt_ipv4_unicast(struct vty *vty, struct lyd_node *dnode,
				      bool show_defaults);
void cli_show_ip_rift_mt_ipv4_multicast(struct vty *vty, struct lyd_node *dnode,
					bool show_defaults);
void cli_show_ip_rift_mt_ipv4_mgmt(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_ip_rift_mt_ipv6_unicast(struct vty *vty, struct lyd_node *dnode,
				      bool show_defaults);
void cli_show_ip_rift_mt_ipv6_multicast(struct vty *vty, struct lyd_node *dnode,
					bool show_defaults);
void cli_show_ip_rift_mt_ipv6_mgmt(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_ip_rift_mt_ipv6_dstsrc(struct vty *vty, struct lyd_node *dnode,
				     bool show_defaults);
void cli_show_ip_rift_circ_type(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults);
void cli_show_ip_rift_network_type(struct vty *vty, struct lyd_node *dnode,
				   bool show_defaults);
void cli_show_ip_rift_priority(struct vty *vty, struct lyd_node *dnode,
			       bool show_defaults);
void cli_show_rift_log_adjacency(struct vty *vty, struct lyd_node *dnode,
				 bool show_defaults);

#endif /* RIFTD_RIFT_CLI_H_ */
