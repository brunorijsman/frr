/*
 * RIFT Rout(e)ing protocol - rift_vty_common.h
 *
 * Copyright (C) 2019        Bruno Rijsman
 *
 * This code is based on the original FRR IS-IS code, which is:
 * 
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 * Copyright (C) 2016        David Lamparter, for NetDEF, Inc.
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

#ifndef RIFT_VTY_COMMON_H
#define RIFT_VTY_COMMON_H

struct rift_circuit *rift_circuit_lookup(struct vty *vty);

void rift_vty_daemon_init(void);
void rift_vty_init(void);

#endif
