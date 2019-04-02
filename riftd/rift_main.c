/*
 * RIFT Rout(e)ing protocol - rift_main.c
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

#include <zebra.h>

#include "getopt.h"
#include "thread.h"
#include "log.h"
#include <lib/version.h>
#include "command.h"
#include "vty.h"
#include "memory.h"
#include "memory_vty.h"
#include "stream.h"
#include "if.h"
#include "privs.h"
#include "sigevent.h"
#include "filter.h"
#include "plist.h"
#include "zclient.h"
#include "vrf.h"
#include "qobj.h"
#include "libfrr.h"

#include "riftd/dict.h"
#include "riftd/rift_constants.h"
#include "riftd/rift_common.h"
#include "riftd/rift_flags.h"
#include "riftd/rift_circuit.h"
#include "riftd/riftd.h"
#include "riftd/rift_dynhn.h"
#include "riftd/rift_spf.h"
#include "riftd/rift_route.h"
#include "riftd/rift_routemap.h"
#include "riftd/rift_zebra.h"
#include "riftd/rift_te.h"
#include "riftd/rift_errors.h"
#include "riftd/rift_vty_common.h"
#include "riftd/rift_bfd.h"
#include "riftd/rift_lsp.h"
#include "riftd/rift_mt.h"

/* Default configuration file name */
#define RIFTD_DEFAULT_CONFIG "riftd.conf"
/* Default vty port */
#define RIFTD_VTY_PORT       2608

/* riftd privileges */
zebra_capabilities_t _caps_p[] = {ZCAP_NET_RAW, ZCAP_BIND};

struct zebra_privs_t riftd_privs = {
#if defined(FRR_USER)
	.user = FRR_USER,
#endif
#if defined FRR_GROUP
	.group = FRR_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0};

/* riftd options */
struct option longopts[] = {{0}};

/* Master of threads. */
struct thread_master *master;

/*
 * Prototypes.
 */
void sighup(void);
void sigint(void);
void sigterm(void);
void sigusr1(void);


static __attribute__((__noreturn__)) void terminate(int i)
{
	rift_zebra_stop();
	exit(i);
}

/*
 * Signal handlers
 */
static struct frr_daemon_info riftd_di;
void sighup(void)
{
	zlog_info("SIGHUP received");

	/* Reload config file. */
	vty_read_config(NULL, riftd_di.config_file, config_default);
}

__attribute__((__noreturn__)) void sigint(void)
{
	zlog_notice("Terminating on signal SIGINT");
	terminate(0);
}

__attribute__((__noreturn__)) void sigterm(void)
{
	zlog_notice("Terminating on signal SIGTERM");
	terminate(0);
}

void sigusr1(void)
{
	zlog_debug("SIGUSR1 received");
	zlog_rotate();
}

struct quagga_signal_t riftd_signals[] = {
	{
		.signal = SIGHUP,
		.handler = &sighup,
	},
	{
		.signal = SIGUSR1,
		.handler = &sigusr1,
	},
	{
		.signal = SIGINT,
		.handler = &sigint,
	},
	{
		.signal = SIGTERM,
		.handler = &sigterm,
	},
};


static const struct frr_yang_module_info *riftd_yang_modules[] = {
	&frr_interface_info,
	&frr_riftd_info,
};

FRR_DAEMON_INFO(riftd, RIFT, 
                .vty_port = RIFTD_VTY_PORT,
		.proghelp = "Implementation of the RIFT routing protocol.",
		.copyright = "Copyright (c) 2019 Bruno Rijsman",
		.signals = riftd_signals,
		.n_signals = array_size(riftd_signals),
		.privs = &riftd_privs,
		.yang_modules = riftd_yang_modules,
		.n_yang_modules = array_size(riftd_yang_modules), )

/*
 * Main routine of riftd. Parse arguments and handle RIFT state machine.
 */
int main(int argc, char **argv, char **envp)
{
	int opt;

	frr_preinit(&riftd_di, argc, argv);
	frr_opt_add("", longopts, "");

	/* Command line argument treatment. */
	while (1) {
		opt = frr_getopt(argc, argv, NULL);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		default:
			frr_help_exit(1);
			break;
		}
	}

	/* thread master */
	master = frr_init();

	/*
	 *  initializations
	 */
	rift_error_init();
	access_list_init();
	vrf_init(NULL, NULL, NULL, NULL, NULL);
	prefix_list_init();
	rift_init();
	rift_circuit_init();
	rift_vty_init();
	rift_cli_init();
	rift_spf_cmds_init();
	rift_redist_init();
	rift_route_map_init();
	rift_mpls_te_init();
	lsp_init();
	mt_init();

	/* create the global 'rift' instance */
	rift_new(1);

	rift_zebra_init(master);
	rift_bfd_init();

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	exit(0);
}
