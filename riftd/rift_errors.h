/*
 * RIFT-specific error messages.
 *
 * Copyright (C) 2019 Bruno Rijsman
 *
 * This code is based on the original FRR IS-IS code, which is:
 * 
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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

#ifndef __RIFT_ERRORS_H__
#define __RIFT_ERRORS_H__

#include "lib/ferr.h"

enum rift_log_refs {
	EC_RIFT_PACKET = RIFT_FERR_START,
	EC_RIFT_CONFIG,
};

extern void rift_error_init(void);

#endif
