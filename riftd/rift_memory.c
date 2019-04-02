/* riftd memory type definitions
 *
 * Copyright (C) 2015  David Lamparter
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rift_memory.h"

DEFINE_MGROUP(RIFTD, "riftd")
DEFINE_MTYPE(RIFTD, RIFT, "RIFT")
DEFINE_MTYPE(RIFTD, RIFT_TMP, "RIFT TMP")
DEFINE_MTYPE(RIFTD, RIFT_CIRCUIT, "RIFT circuit")
DEFINE_MTYPE(RIFTD, RIFT_LSP, "RIFT LSP")
DEFINE_MTYPE(RIFTD, RIFT_ADJACENCY, "RIFT adjacency")
DEFINE_MTYPE(RIFTD, RIFT_ADJACENCY_INFO, "RIFT adjacency info")
DEFINE_MTYPE(RIFTD, RIFT_AREA, "RIFT area")
DEFINE_MTYPE(RIFTD, RIFT_AREA_ADDR, "RIFT area address")
DEFINE_MTYPE(RIFTD, RIFT_DYNHN, "RIFT dyn hostname")
DEFINE_MTYPE(RIFTD, RIFT_SPFTREE, "RIFT SPFtree")
DEFINE_MTYPE(RIFTD, RIFT_VERTEX, "RIFT vertex")
DEFINE_MTYPE(RIFTD, RIFT_ROUTE_INFO, "RIFT route info")
DEFINE_MTYPE(RIFTD, RIFT_NEXTHOP, "RIFT nexthop")
DEFINE_MTYPE(RIFTD, RIFT_NEXTHOP6, "RIFT nexthop6")
DEFINE_MTYPE(RIFTD, RIFT_DICT, "RIFT dictionary")
DEFINE_MTYPE(RIFTD, RIFT_DICT_NODE, "RIFT dictionary node")
DEFINE_MTYPE(RIFTD, RIFT_EXT_ROUTE, "RIFT redistributed route")
DEFINE_MTYPE(RIFTD, RIFT_EXT_INFO, "RIFT redistributed route info")
DEFINE_MTYPE(RIFTD, RIFT_MPLS_TE, "RIFT MPLS_TE parameters")
