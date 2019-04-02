/*
 * RIFT Rout(e)ing protocol - rift_dr.c
 *                             RIFT designated router related routines
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


#include <zebra.h>

#include "log.h"
#include "hash.h"
#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "stream.h"
#include "if.h"

#include "riftd/dict.h"
#include "riftd/rift_constants.h"
#include "riftd/rift_common.h"
#include "riftd/rift_misc.h"
#include "riftd/rift_flags.h"
#include "riftd/rift_circuit.h"
#include "riftd/riftd.h"
#include "riftd/rift_adjacency.h"
#include "riftd/rift_constants.h"
#include "riftd/rift_pdu.h"
#include "riftd/rift_lsp.h"
#include "riftd/rift_dr.h"
#include "riftd/rift_events.h"

const char *rift_disflag2string(int disflag)
{

	switch (disflag) {
	case RIFT_IS_NOT_DIS:
		return "is not DIS";
	case RIFT_IS_DIS:
		return "is DIS";
	case RIFT_WAS_DIS:
		return "was DIS";
	default:
		return "unknown DIS state";
	}
	return NULL; /* not reached */
}

int rift_run_dr(struct thread *thread)
{
	struct rift_circuit_arg *arg = THREAD_ARG(thread);

	assert(arg);

	struct rift_circuit *circuit = arg->circuit;
	int level = arg->level;

	assert(circuit);

	if (circuit->circ_type != CIRCUIT_T_BROADCAST) {
		zlog_warn("%s: scheduled for non broadcast circuit from %s:%d",
			  __func__, thread->schedfrom, thread->schedfrom_line);
		return RIFT_WARNING;
	}

	if (circuit->u.bc.run_dr_elect[level - 1])
		zlog_warn("rift_run_dr(): run_dr_elect already set for l%d", level);

	circuit->u.bc.t_run_dr[level - 1] = NULL;
	circuit->u.bc.run_dr_elect[level - 1] = 1;

	return RIFT_OK;
}

static int rift_check_dr_change(struct rift_adjacency *adj, int level)
{
	int i;

	if (adj->dis_record[level - 1].dis
	    != adj->dis_record[(1 * RIFT_LEVELS) + level - 1].dis)
	/* was there a DIS state transition ? */
	{
		adj->dischanges[level - 1]++;
		/* ok rotate the history list through */
		for (i = DIS_RECORDS - 1; i > 0; i--) {
			adj->dis_record[(i * RIFT_LEVELS) + level - 1].dis =
				adj->dis_record[((i - 1) * RIFT_LEVELS) + level
						- 1]
					.dis;
			adj->dis_record[(i * RIFT_LEVELS) + level - 1]
				.last_dis_change =
				adj->dis_record[((i - 1) * RIFT_LEVELS) + level
						- 1]
					.last_dis_change;
		}
	}
	return RIFT_OK;
}

int rift_dr_elect(struct rift_circuit *circuit, int level)
{
	struct list *adjdb;
	struct listnode *node;
	struct rift_adjacency *adj, *adj_dr = NULL;
	struct list *list = list_new();
	uint8_t own_prio;
	int biggest_prio = -1;
	int cmp_res, retval = RIFT_OK;

	own_prio = circuit->priority[level - 1];
	adjdb = circuit->u.bc.adjdb[level - 1];

	if (!adjdb) {
		zlog_warn("rift_dr_elect() adjdb == NULL");
		list_delete(&list);
		return RIFT_WARNING;
	}
	rift_adj_build_up_list(adjdb, list);

	/*
	 * Loop the adjacencies and find the one with the biggest priority
	 */
	for (ALL_LIST_ELEMENTS_RO(list, node, adj)) {
		/* clear flag for show output */
		adj->dis_record[level - 1].dis = RIFT_IS_NOT_DIS;
		adj->dis_record[level - 1].last_dis_change = time(NULL);

		if (adj->prio[level - 1] > biggest_prio) {
			biggest_prio = adj->prio[level - 1];
			adj_dr = adj;
		} else if (adj->prio[level - 1] == biggest_prio) {
			/*
			 * Comparison of MACs breaks a tie
			 */
			if (adj_dr) {
				cmp_res = memcmp(adj_dr->snpa, adj->snpa,
						 ETH_ALEN);
				if (cmp_res < 0) {
					adj_dr = adj;
				}
				if (cmp_res == 0)
					zlog_warn(
						"rift_dr_elect(): multiple adjacencies with same SNPA");
			} else {
				adj_dr = adj;
			}
		}
	}

	if (!adj_dr) {
		/*
		 * Could not find the DR - means we are alone. Resign if we were
		 * DR.
		 */
		if (circuit->u.bc.is_dr[level - 1])
			retval = rift_dr_resign(circuit, level);
		list_delete(&list);
		return retval;
	}

	/*
	 * Now we have the DR adjacency, compare it to self
	 */
	if (adj_dr->prio[level - 1] < own_prio
	    || (adj_dr->prio[level - 1] == own_prio
		&& memcmp(adj_dr->snpa, circuit->u.bc.snpa, ETH_ALEN) < 0)) {
		adj_dr->dis_record[level - 1].dis = RIFT_IS_NOT_DIS;
		adj_dr->dis_record[level - 1].last_dis_change = time(NULL);

		/* rotate the history log */
		for (ALL_LIST_ELEMENTS_RO(list, node, adj))
			rift_check_dr_change(adj, level);

		/* We are the DR, commence DR */
		if (circuit->u.bc.is_dr[level - 1] == 0 && listcount(list) > 0)
			retval = rift_dr_commence(circuit, level);
	} else {
		/* ok we have found the DIS - lets mark the adjacency */
		/* set flag for show output */
		adj_dr->dis_record[level - 1].dis = RIFT_IS_DIS;
		adj_dr->dis_record[level - 1].last_dis_change = time(NULL);

		/* now loop through a second time to check if there has been a
		 * DIS change
		 * if yes rotate the history log
		 */

		for (ALL_LIST_ELEMENTS_RO(list, node, adj))
			rift_check_dr_change(adj, level);

		/*
		 * We are not DR - if we were -> resign
		 */
		if (circuit->u.bc.is_dr[level - 1])
			retval = rift_dr_resign(circuit, level);
	}
	list_delete(&list);
	return retval;
}

int rift_dr_resign(struct rift_circuit *circuit, int level)
{
	uint8_t id[RIFT_SYS_ID_LEN + 2];

	zlog_debug("rift_dr_resign l%d", level);

	circuit->u.bc.is_dr[level - 1] = 0;
	circuit->u.bc.run_dr_elect[level - 1] = 0;
	THREAD_TIMER_OFF(circuit->u.bc.t_run_dr[level - 1]);
	THREAD_TIMER_OFF(circuit->u.bc.t_refresh_pseudo_lsp[level - 1]);
	circuit->lsp_regenerate_pending[level - 1] = 0;

	memcpy(id, rift->sysid, RIFT_SYS_ID_LEN);
	LSP_PSEUDO_ID(id) = circuit->circuit_id;
	LSP_FRAGMENT(id) = 0;
	lsp_purge_pseudo(id, circuit, level);

	if (level == 1) {
		memset(circuit->u.bc.l1_desig_is, 0, RIFT_SYS_ID_LEN + 1);

		thread_add_timer(master, send_l1_psnp, circuit,
				 rift_jitter(circuit->psnp_interval[level - 1],
					     PSNP_JITTER),
				 &circuit->t_send_psnp[0]);
	} else {
		memset(circuit->u.bc.l2_desig_is, 0, RIFT_SYS_ID_LEN + 1);

		thread_add_timer(master, send_l2_psnp, circuit,
				 rift_jitter(circuit->psnp_interval[level - 1],
					     PSNP_JITTER),
				 &circuit->t_send_psnp[1]);
	}

	THREAD_TIMER_OFF(circuit->t_send_csnp[level - 1]);

	thread_add_timer(master, rift_run_dr,
			 &circuit->level_arg[level - 1],
			 2 * circuit->hello_interval[level - 1],
			 &circuit->u.bc.t_run_dr[level - 1]);


	thread_add_event(master, rift_event_dis_status_change, circuit, 0,
			 NULL);

	return RIFT_OK;
}

int rift_dr_commence(struct rift_circuit *circuit, int level)
{
	uint8_t old_dr[RIFT_SYS_ID_LEN + 2];

	if (rift->debugs & DEBUG_EVENTS)
		zlog_debug("rift_dr_commence l%d", level);

	/* Lets keep a pause in DR election */
	circuit->u.bc.run_dr_elect[level - 1] = 0;
	circuit->u.bc.is_dr[level - 1] = 1;

	if (level == 1) {
		memcpy(old_dr, circuit->u.bc.l1_desig_is, RIFT_SYS_ID_LEN + 1);
		LSP_FRAGMENT(old_dr) = 0;
		if (LSP_PSEUDO_ID(old_dr)) {
			/* there was a dr elected, purge its LSPs from the db */
			lsp_purge_pseudo(old_dr, circuit, level);
		}
		memcpy(circuit->u.bc.l1_desig_is, rift->sysid, RIFT_SYS_ID_LEN);
		*(circuit->u.bc.l1_desig_is + RIFT_SYS_ID_LEN) =
			circuit->circuit_id;

		assert(circuit->circuit_id); /* must be non-zero */
		/*    if (circuit->t_send_l1_psnp)
		   thread_cancel (circuit->t_send_l1_psnp); */
		lsp_generate_pseudo(circuit, 1);

		thread_add_timer(master, send_l1_csnp, circuit,
				 rift_jitter(circuit->csnp_interval[level - 1],
					     CSNP_JITTER),
				 &circuit->t_send_csnp[0]);

	} else {
		memcpy(old_dr, circuit->u.bc.l2_desig_is, RIFT_SYS_ID_LEN + 1);
		LSP_FRAGMENT(old_dr) = 0;
		if (LSP_PSEUDO_ID(old_dr)) {
			/* there was a dr elected, purge its LSPs from the db */
			lsp_purge_pseudo(old_dr, circuit, level);
		}
		memcpy(circuit->u.bc.l2_desig_is, rift->sysid, RIFT_SYS_ID_LEN);
		*(circuit->u.bc.l2_desig_is + RIFT_SYS_ID_LEN) =
			circuit->circuit_id;

		assert(circuit->circuit_id); /* must be non-zero */
		/*    if (circuit->t_send_l1_psnp)
		   thread_cancel (circuit->t_send_l1_psnp); */
		lsp_generate_pseudo(circuit, 2);

		thread_add_timer(master, send_l2_csnp, circuit,
				 rift_jitter(circuit->csnp_interval[level - 1],
					     CSNP_JITTER),
				 &circuit->t_send_csnp[1]);
	}

	thread_add_timer(master, rift_run_dr,
			 &circuit->level_arg[level - 1],
			 2 * circuit->hello_interval[level - 1],
			 &circuit->u.bc.t_run_dr[level - 1]);
	thread_add_event(master, rift_event_dis_status_change, circuit, 0,
			 NULL);

	return RIFT_OK;
}
