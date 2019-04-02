/*
 * RIFT Rout(e)ing protocol - rift_dr.h
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

#ifndef _ZEBRA_RIFT_DR_H
#define _ZEBRA_RIFT_DR_H

int rift_run_dr(struct thread *thread);
int rift_dr_elect(struct rift_circuit *circuit, int level);
int rift_dr_resign(struct rift_circuit *circuit, int level);
int rift_dr_commence(struct rift_circuit *circuit, int level);
const char *rift_disflag2string(int disflag);

enum rift_dis_state {
	RIFT_IS_NOT_DIS,
	RIFT_IS_DIS,
	RIFT_WAS_DIS,
	RIFT_UNKNOWN_DIS
};

#endif /* _ZEBRA_RIFT_DR_H */
