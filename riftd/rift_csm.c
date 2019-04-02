/*
 * RIFT Rout(e)ing protocol - rift_csm.c
 *                             RIFT circuit state machine
 *
 * Copyright (C) 2019         Bruno Rijsman
 *
 * This code is based on the original FRR IS-IS code, which is:
 * 
 * Copyright (C) 2001,2002    Sampo Saaristo
 *                            Tampere University of Technology
 *                            Institute of Communications Engineering
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

#include "log.h"
#include "memory.h"
#include "if.h"
#include "linklist.h"
#include "command.h"
#include "thread.h"
#include "hash.h"
#include "prefix.h"
#include "stream.h"

#include "riftd/dict.h"
#include "riftd/rift_constants.h"
#include "riftd/rift_common.h"
#include "riftd/rift_flags.h"
#include "riftd/rift_circuit.h"
#include "riftd/rift_lsp.h"
#include "riftd/rift_pdu.h"
#include "riftd/rift_network.h"
#include "riftd/rift_misc.h"
#include "riftd/rift_constants.h"
#include "riftd/rift_adjacency.h"
#include "riftd/rift_dr.h"
#include "riftd/riftd.h"
#include "riftd/rift_csm.h"
#include "riftd/rift_events.h"
#include "riftd/rift_errors.h"

extern struct rift *rift;

static const char *csm_statestr[] = {"C_STATE_NA", "C_STATE_INIT",
				     "C_STATE_CONF", "C_STATE_UP"};

#define STATE2STR(S) csm_statestr[S]

static const char *csm_eventstr[] = {
	"NO_STATE",     "RIFT_ENABLE",    "IF_UP_FROM_Z",
	"RIFT_DISABLE", "IF_DOWN_FROM_Z",
};

#define EVENT2STR(E) csm_eventstr[E]

struct rift_circuit *
rift_csm_state_change(int event, struct rift_circuit *circuit, void *arg)
{
	int old_state;

	old_state = circuit ? circuit->state : C_STATE_NA;
	if (rift->debugs & DEBUG_EVENTS)
		zlog_debug("CSM_EVENT: %s", EVENT2STR(event));

	switch (old_state) {
	case C_STATE_NA:
		if (circuit)
			zlog_warn("Non-null circuit while state C_STATE_NA");
		assert(circuit == NULL);
		switch (event) {
		case RIFT_ENABLE:
			circuit = rift_circuit_new();
			rift_circuit_configure(circuit,
					       (struct rift_area *)arg);
			circuit->state = C_STATE_CONF;
			break;
		case IF_UP_FROM_Z:
			circuit = rift_circuit_new();
			rift_circuit_if_add(circuit, (struct interface *)arg);
			listnode_add(rift->init_circ_list, circuit);
			circuit->state = C_STATE_INIT;
			break;
		case RIFT_DISABLE:
			zlog_warn("circuit already disabled");
			break;
		case IF_DOWN_FROM_Z:
			zlog_warn("circuit already disconnected");
			break;
		}
		break;
	case C_STATE_INIT:
		assert(circuit);
		switch (event) {
		case RIFT_ENABLE:
			rift_circuit_configure(circuit,
					       (struct rift_area *)arg);
			if (rift_circuit_up(circuit) != RIFT_OK) {
				rift_circuit_deconfigure(
					circuit, (struct rift_area *)arg);
				break;
			}
			circuit->state = C_STATE_UP;
			rift_event_circuit_state_change(circuit, circuit->area,
							1);
			listnode_delete(rift->init_circ_list, circuit);
			break;
		case IF_UP_FROM_Z:
			assert(circuit);
			zlog_warn("circuit already connected");
			break;
		case RIFT_DISABLE:
			zlog_warn("circuit already disabled");
			break;
		case IF_DOWN_FROM_Z:
			rift_circuit_if_del(circuit, (struct interface *)arg);
			listnode_delete(rift->init_circ_list, circuit);
			rift_circuit_del(circuit);
			circuit = NULL;
			break;
		}
		break;
	case C_STATE_CONF:
		assert(circuit);
		switch (event) {
		case RIFT_ENABLE:
			zlog_warn("circuit already enabled");
			break;
		case IF_UP_FROM_Z:
			rift_circuit_if_add(circuit, (struct interface *)arg);
			if (rift_circuit_up(circuit) != RIFT_OK) {
				flog_err(
					EC_RIFT_CONFIG,
					"Could not bring up %s because of invalid config.",
					circuit->interface->name);
				flog_err(
					EC_RIFT_CONFIG,
					"Clearing config for %s. Please re-examine it.",
					circuit->interface->name);
				if (circuit->ip_router) {
					circuit->ip_router = 0;
					circuit->area->ip_circuits--;
				}
				if (circuit->ipv6_router) {
					circuit->ipv6_router = 0;
					circuit->area->ipv6_circuits--;
				}
				circuit_update_nlpids(circuit);
				rift_circuit_deconfigure(circuit,
							 circuit->area);
				listnode_add(rift->init_circ_list, circuit);
				circuit->state = C_STATE_INIT;
				break;
			}
			circuit->state = C_STATE_UP;
			rift_event_circuit_state_change(circuit, circuit->area,
							1);
			break;
		case RIFT_DISABLE:
			rift_circuit_deconfigure(circuit,
						 (struct rift_area *)arg);
			rift_circuit_del(circuit);
			circuit = NULL;
			break;
		case IF_DOWN_FROM_Z:
			zlog_warn("circuit already disconnected");
			break;
		}
		break;
	case C_STATE_UP:
		assert(circuit);
		switch (event) {
		case RIFT_ENABLE:
			zlog_warn("circuit already configured");
			break;
		case IF_UP_FROM_Z:
			zlog_warn("circuit already connected");
			break;
		case RIFT_DISABLE:
			rift_circuit_down(circuit);
			rift_circuit_deconfigure(circuit,
						 (struct rift_area *)arg);
			circuit->state = C_STATE_INIT;
			rift_event_circuit_state_change(
				circuit, (struct rift_area *)arg, 0);
			listnode_add(rift->init_circ_list, circuit);
			break;
		case IF_DOWN_FROM_Z:
			rift_circuit_down(circuit);
			rift_circuit_if_del(circuit, (struct interface *)arg);
			circuit->state = C_STATE_CONF;
			rift_event_circuit_state_change(circuit, circuit->area,
							0);
			break;
		}
		break;

	default:
		zlog_warn("Invalid circuit state %d", old_state);
	}

	if (rift->debugs & DEBUG_EVENTS)
		zlog_debug("CSM_STATE_CHANGE: %s -> %s ", STATE2STR(old_state),
			   circuit ? STATE2STR(circuit->state)
				   : STATE2STR(C_STATE_NA));

	return circuit;
}
