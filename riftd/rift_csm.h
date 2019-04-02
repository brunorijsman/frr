/*
 * RIFT Rout(e)ing protocol - rift_csm.h
 *                             RIFT circuit state machine
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
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
#ifndef _ZEBRA_RIFT_CSM_H
#define _ZEBRA_RIFT_CSM_H

/*
 * Circuit states
 */
#define C_STATE_NA   0
#define C_STATE_INIT 1		/* Connected to interface */
#define C_STATE_CONF 2		/* Configured for RIFT    */
#define C_STATE_UP   3		/* CONN | CONF            */

/*
 * Circuit events
 */
#define RIFT_ENABLE    1
#define IF_UP_FROM_Z   2
#define RIFT_DISABLE   3
#define IF_DOWN_FROM_Z 4

struct rift_circuit *
rift_csm_state_change(int event, struct rift_circuit *circuit, void *arg);

#endif /* _ZEBRA_RIFT_CSM_H */
