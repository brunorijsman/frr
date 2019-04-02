/* riftd memory type declarations
 *
 * Copyright (C) 2019  Bruno Rijsman
 *
 * This code is based on the original FRR IS-IS code, which is:
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

#ifndef _QUAGGA_RIFT_MEMORY_H
#define _QUAGGA_RIFT_MEMORY_H

#include "memory.h"

DECLARE_MGROUP(RIFTD)
DECLARE_MTYPE(RIFT)
DECLARE_MTYPE(RIFT_TMP)
DECLARE_MTYPE(RIFT_CIRCUIT)
DECLARE_MTYPE(RIFT_LSP)
DECLARE_MTYPE(RIFT_ADJACENCY)
DECLARE_MTYPE(RIFT_ADJACENCY_INFO)
DECLARE_MTYPE(RIFT_AREA)
DECLARE_MTYPE(RIFT_AREA_ADDR)
DECLARE_MTYPE(RIFT_DYNHN)
DECLARE_MTYPE(RIFT_SPFTREE)
DECLARE_MTYPE(RIFT_VERTEX)
DECLARE_MTYPE(RIFT_ROUTE_INFO)
DECLARE_MTYPE(RIFT_NEXTHOP)
DECLARE_MTYPE(RIFT_NEXTHOP6)
DECLARE_MTYPE(RIFT_DICT)
DECLARE_MTYPE(RIFT_DICT_NODE)
DECLARE_MTYPE(RIFT_EXT_ROUTE)
DECLARE_MTYPE(RIFT_EXT_INFO)
DECLARE_MTYPE(RIFT_MPLS_TE)

#endif /* _QUAGGA_RIFT_MEMORY_H */
