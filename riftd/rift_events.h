/*
 * RIFT Rout(e)ing protocol - rift_events.h
 *
 * Copyright (C) 2019        Bruno Rijsman
 *
 * This code is based on the original FRR IS-IS code, which is:
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
#ifndef _ZEBRA_RIFT_EVENTS_H
#define _ZEBRA_RIFT_EVENTS_H

/*
 * Events related to circuit
 */
void rift_event_circuit_state_change(struct rift_circuit *circuit,
				     struct rift_area *area, int state);
void rift_event_circuit_type_change(struct rift_circuit *circuit, int newtype);
/*
 * Events related to adjacencies
 */
int rift_event_dis_status_change(struct thread *thread);

/*
 * Error events
 */
#define AUTH_ERROR_TYPE_LSP   3
#define AUTH_ERROR_TYPE_SNP   2
#define AUTH_ERROR_TYPE_HELLO 1
void rift_event_auth_failure(char *area_tag, const char *error_string,
			     uint8_t *sysid);

#endif /* _ZEBRA_RIFT_EVENTS_H */
