/*
 * RIFT Rout(e)ing protocol - rift_lsp.h
 *                             LSP processing
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

#ifndef _ZEBRA_RIFT_LSP_H
#define _ZEBRA_RIFT_LSP_H

#include "riftd/rift_pdu.h"

/* Structure for rift_lsp, this structure will only support the fixed
 * System ID (Currently 6) (atleast for now). In order to support more
 * We will have to split the header into two parts, and for readability
 * sake it should better be avoided */
struct rift_lsp {
	struct rift_lsp_hdr hdr;
	struct stream *pdu; /* full pdu lsp */
	union {
		struct list *frags;
		struct rift_lsp *zero_lsp;
	} lspu;
	uint32_t SSNflags[RIFT_MAX_CIRCUITS];
	int level;     /* L1 or L2? */
	int scheduled; /* scheduled for sending */
	time_t installed;
	time_t last_generated;
	int own_lsp;
	/* used for 60 second counting when rem_lifetime is zero */
	int age_out;
	struct rift_area *area;
	struct rift_tlvs *tlvs;

	time_t flooding_time;
	struct list *flooding_neighbors[TX_LSP_CIRCUIT_SCOPED + 1];
	char *flooding_interface;
	bool flooding_circuit_scoped;
};

dict_t *lsp_db_init(void);
void lsp_db_destroy(dict_t *lspdb);
int lsp_tick(struct thread *thread);

int lsp_generate(struct rift_area *area, int level);
#define lsp_regenerate_schedule(area, level, all_pseudo) \
	_lsp_regenerate_schedule((area), (level), (all_pseudo), true, \
				 __func__, __FILE__, __LINE__)
int _lsp_regenerate_schedule(struct rift_area *area, int level,
			     int all_pseudo, bool postpone,
			     const char *func, const char *file, int line);
int lsp_generate_pseudo(struct rift_circuit *circuit, int level);
int lsp_regenerate_schedule_pseudo(struct rift_circuit *circuit, int level);

struct rift_lsp *lsp_new(struct rift_area *area, uint8_t *lsp_id,
			 uint16_t rem_lifetime, uint32_t seq_num,
			 uint8_t lsp_bits, uint16_t checksum,
			 struct rift_lsp *lsp0, int level);
struct rift_lsp *lsp_new_from_recv(struct rift_lsp_hdr *hdr,
				   struct rift_tlvs *tlvs,
				   struct stream *stream, struct rift_lsp *lsp0,
				   struct rift_area *area, int level);
void lsp_insert(struct rift_lsp *lsp, dict_t *lspdb);
struct rift_lsp *lsp_search(uint8_t *id, dict_t *lspdb);

void lsp_build_list(uint8_t *start_id, uint8_t *stop_id, uint8_t num_lsps,
		    struct list *list, dict_t *lspdb);
void lsp_build_list_nonzero_ht(uint8_t *start_id, uint8_t *stop_id,
			       struct list *list, dict_t *lspdb);
void lsp_search_and_destroy(uint8_t *id, dict_t *lspdb);
void lsp_purge_pseudo(uint8_t *id, struct rift_circuit *circuit, int level);
void lsp_purge_non_exist(int level, struct rift_lsp_hdr *hdr,
			 struct rift_area *area);

#define LSP_EQUAL 1
#define LSP_NEWER 2
#define LSP_OLDER 3

#define LSP_PSEUDO_ID(I) ((I)[RIFT_SYS_ID_LEN])
#define LSP_FRAGMENT(I) ((I)[RIFT_SYS_ID_LEN + 1])
#define OWNLSPID(I)                                                            \
	memcpy((I), rift->sysid, RIFT_SYS_ID_LEN);                             \
	(I)[RIFT_SYS_ID_LEN] = 0;                                              \
	(I)[RIFT_SYS_ID_LEN + 1] = 0
int lsp_id_cmp(uint8_t *id1, uint8_t *id2);
int lsp_compare(char *areatag, struct rift_lsp *lsp, uint32_t seqno,
		uint16_t checksum, uint16_t rem_lifetime);
void lsp_update(struct rift_lsp *lsp, struct rift_lsp_hdr *hdr,
		struct rift_tlvs *tlvs, struct stream *stream,
		struct rift_area *area, int level, bool confusion);
void lsp_inc_seqno(struct rift_lsp *lsp, uint32_t seqno);
void lspid_print(uint8_t *lsp_id, char *dest, char dynhost, char frag);
void lsp_print(struct rift_lsp *lsp, struct vty *vty, char dynhost);
void lsp_print_detail(struct rift_lsp *lsp, struct vty *vty, char dynhost);
int lsp_print_all(struct vty *vty, dict_t *lspdb, char detail, char dynhost);
/* sets SRMflags for all active circuits of an lsp */
void lsp_set_all_srmflags(struct rift_lsp *lsp, bool set);

#define lsp_flood(lsp, circuit) \
	_lsp_flood((lsp), (circuit), __func__, __FILE__, __LINE__)
void _lsp_flood(struct rift_lsp *lsp, struct rift_circuit *circuit,
		const char *func, const char *file, int line);
void lsp_init(void);

#endif /* RIFT_LSP */
