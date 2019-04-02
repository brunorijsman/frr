/*
 * RIFT Rout(e)ing protocol - LSP TX Queuing logic
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
#include <zebra.h>

#include "hash.h"
#include "jhash.h"

#include "riftd/riftd.h"
#include "riftd/rift_memory.h"
#include "riftd/rift_flags.h"
#include "dict.h"
#include "riftd/rift_circuit.h"
#include "riftd/rift_lsp.h"
#include "riftd/rift_misc.h"
#include "riftd/rift_tx_queue.h"

DEFINE_MTYPE_STATIC(RIFTD, TX_QUEUE, "RIFT TX Queue")
DEFINE_MTYPE_STATIC(RIFTD, TX_QUEUE_ENTRY, "RIFT TX Queue Entry")

struct rift_tx_queue {
	struct rift_circuit *circuit;
	void (*send_event)(struct rift_circuit *circuit,
			   struct rift_lsp *, enum rift_tx_type);
	struct hash *hash;
};

struct rift_tx_queue_entry {
	struct rift_lsp *lsp;
	enum rift_tx_type type;
	bool is_retry;
	struct thread *retry;
	struct rift_tx_queue *queue;
};

static unsigned tx_queue_hash_key(void *p)
{
	struct rift_tx_queue_entry *e = p;

	uint32_t id_key = jhash(e->lsp->hdr.lsp_id,
				RIFT_SYS_ID_LEN + 2, 0x55aa5a5a);

	return jhash_1word(e->lsp->level, id_key);
}

static bool tx_queue_hash_cmp(const void *a, const void *b)
{
	const struct rift_tx_queue_entry *ea = a, *eb = b;

	if (ea->lsp->level != eb->lsp->level)
		return false;

	if (memcmp(ea->lsp->hdr.lsp_id, eb->lsp->hdr.lsp_id,
		   RIFT_SYS_ID_LEN + 2))
		return false;

	return true;
}

struct rift_tx_queue *rift_tx_queue_new(
		struct rift_circuit *circuit,
		void(*send_event)(struct rift_circuit *circuit,
				  struct rift_lsp *,
				  enum rift_tx_type))
{
	struct rift_tx_queue *rv = XCALLOC(MTYPE_TX_QUEUE, sizeof(*rv));

	rv->circuit = circuit;
	rv->send_event = send_event;

	rv->hash = hash_create(tx_queue_hash_key, tx_queue_hash_cmp, NULL);
	return rv;
}

static void tx_queue_element_free(void *element)
{
	struct rift_tx_queue_entry *e = element;

	if (e->retry)
		thread_cancel(e->retry);

	XFREE(MTYPE_TX_QUEUE_ENTRY, e);
}

void rift_tx_queue_free(struct rift_tx_queue *queue)
{
	hash_clean(queue->hash, tx_queue_element_free);
	hash_free(queue->hash);
	XFREE(MTYPE_TX_QUEUE, queue);
}

static struct rift_tx_queue_entry *tx_queue_find(struct rift_tx_queue *queue,
						 struct rift_lsp *lsp)
{
	struct rift_tx_queue_entry e = {
		.lsp = lsp
	};

	return hash_lookup(queue->hash, &e);
}

static int tx_queue_send_event(struct thread *thread)
{
	struct rift_tx_queue_entry *e = THREAD_ARG(thread);
	struct rift_tx_queue *queue = e->queue;

	e->retry = NULL;
	thread_add_timer(master, tx_queue_send_event, e, 5, &e->retry);

	if (e->is_retry)
		queue->circuit->area->lsp_rxmt_count++;
	else
		e->is_retry = true;

	queue->send_event(queue->circuit, e->lsp, e->type);
	/* Don't access e here anymore, send_event might have destroyed it */

	return 0;
}

void _rift_tx_queue_add(struct rift_tx_queue *queue,
			struct rift_lsp *lsp,
			enum rift_tx_type type,
			const char *func, const char *file,
			int line)
{
	if (!queue)
		return;

	if (rift->debugs & DEBUG_TX_QUEUE) {
		zlog_debug("Add LSP %s to %s queue as %s LSP. (From %s %s:%d)",
			   rawlspid_print(lsp->hdr.lsp_id),
			   queue->circuit->interface->name,
			   (type == TX_LSP_CIRCUIT_SCOPED) ?
			   "circuit scoped" : "regular",
			   func, file, line);
	}

	struct rift_tx_queue_entry *e = tx_queue_find(queue, lsp);
	if (!e) {
		e = XCALLOC(MTYPE_TX_QUEUE_ENTRY, sizeof(*e));
		e->lsp = lsp;
		e->queue = queue;

		struct rift_tx_queue_entry *inserted;
		inserted = hash_get(queue->hash, e, hash_alloc_intern);
		assert(inserted == e);
	}

	e->type = type;

	if (e->retry)
		thread_cancel(e->retry);
	thread_add_event(master, tx_queue_send_event, e, 0, &e->retry);

	e->is_retry = false;
}

void _rift_tx_queue_del(struct rift_tx_queue *queue, struct rift_lsp *lsp,
			const char *func, const char *file, int line)
{
	if (!queue)
		return;

	struct rift_tx_queue_entry *e = tx_queue_find(queue, lsp);
	if (!e)
		return;

	if (rift->debugs & DEBUG_TX_QUEUE) {
		zlog_debug("Remove LSP %s from %s queue. (From %s %s:%d)",
			   rawlspid_print(lsp->hdr.lsp_id),
			   queue->circuit->interface->name,
			   func, file, line);
	}

	if (e->retry)
		thread_cancel(e->retry);

	hash_release(queue->hash, e);
	XFREE(MTYPE_TX_QUEUE_ENTRY, e);
}

unsigned long rift_tx_queue_len(struct rift_tx_queue *queue)
{
	if (!queue)
		return 0;

	return hashcount(queue->hash);
}

void rift_tx_queue_clean(struct rift_tx_queue *queue)
{
	hash_clean(queue->hash, tx_queue_element_free);
}
