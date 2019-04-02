/*
 * RIFT Rout(e)ing protocol - rift_network.h
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


#ifndef _ZEBRA_RIFT_NETWORK_H
#define _ZEBRA_RIFT_NETWORK_H

extern uint8_t ALL_L1_ISYSTEMS[];
extern uint8_t ALL_L2_ISYSTEMS[];

int rift_sock_init(struct rift_circuit *circuit);

int rift_recv_pdu_bcast(struct rift_circuit *circuit, uint8_t *ssnpa);
int rift_recv_pdu_p2p(struct rift_circuit *circuit, uint8_t *ssnpa);
int rift_send_pdu_bcast(struct rift_circuit *circuit, int level);
int rift_send_pdu_p2p(struct rift_circuit *circuit, int level);

#endif /* _ZEBRA_RIFT_NETWORK_H */
