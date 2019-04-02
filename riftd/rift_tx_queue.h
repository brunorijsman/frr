/*
 * RIFT Rout(e)ing protocol - LSP TX Queuing logic
 *
 * Copyright (C) 2019 Bruno Rijsman
 *
 * This code is based on the original FRR IS-IS code, which is:
 * 
 * Copyright (C) 2018 Christian Franke
 *
 * This file is part of FreeRangeRouting (FRR)
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef RIFT_TX_QUEUE_H
#define RIFT_TX_QUEUE_H

enum rift_tx_type {
	TX_LSP_NORMAL = 0,
	TX_LSP_CIRCUIT_SCOPED
};

struct rift_tx_queue;

struct rift_tx_queue *rift_tx_queue_new(
		struct rift_circuit *circuit,
		void(*send_event)(struct rift_circuit *circuit,
				  struct rift_lsp *,
				  enum rift_tx_type)
);

void rift_tx_queue_free(struct rift_tx_queue *queue);

#define rift_tx_queue_add(queue, lsp, type) \
	_rift_tx_queue_add((queue), (lsp), (type), \
			   __func__, __FILE__, __LINE__)
void _rift_tx_queue_add(struct rift_tx_queue *queue, struct rift_lsp *lsp,
			enum rift_tx_type type, const char *func,
			const char *file, int line);

#define rift_tx_queue_del(queue, lsp) \
	_rift_tx_queue_del((queue), (lsp), __func__, __FILE__, __LINE__)
void _rift_tx_queue_del(struct rift_tx_queue *queue, struct rift_lsp *lsp,
			const char *func, const char *file, int line);

unsigned long rift_tx_queue_len(struct rift_tx_queue *queue);

void rift_tx_queue_clean(struct rift_tx_queue *queue);

#endif
