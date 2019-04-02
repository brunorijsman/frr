RIFT-TODO: Update documentation

.. _rift:

****
RIFT
****

:abbr:`RIFT (Routing In Fat Trees)` is a routing protocol
which is described in draft-ietf-rift-rift-04. RIFT is an
:abbr:`IGP (Interior Gateway Protocol)`. Compared with :abbr:`RIP`,
:abbr:`RIFT` can provide scalable network support and faster convergence times
like :abbr:`OSPF`. RIFT is optimized for data center networks.

.. _configuring-riftd:

Configuring riftd
=================

There are no *riftd* specific options. Common options can be specified
(:ref:`common-invocation-options`) to *riftd*. *riftd* needs to acquire
interface information from *zebra* in order to function. Therefore *zebra* must
be running before invoking *riftd*. Also, if *zebra* is restarted then *riftd*
must be too.

Like other daemons, *riftd* configuration is done in :abbr:`RIFT` specific
configuration file :file:`riftd.conf`.

.. _rift-router:

RIFT router
===========

To start the RIFT process you have to specify the RIFT router. As of this
writing, *riftd* does not support multiple RIFT processes.

.. index:: [no] router rift WORD
.. clicmd:: [no] router rift WORD

   Enable or disable the RIFT process by specifying the RIFT domain with
   'WORD'.  *riftd* does not yet support multiple RIFT processes but you must
   specify the name of RIFT process. The RIFT process name 'WORD' is then used
   for interface (see command :clicmd:`ip router rift WORD`).

.. index:: net XX.XXXX. ... .XXX.XX
.. clicmd:: net XX.XXXX. ... .XXX.XX

.. index:: no net XX.XXXX. ... .XXX.XX
.. clicmd:: no net XX.XXXX. ... .XXX.XX

   Set/Unset network entity title (NET) provided in ISO format.

.. index:: hostname dynamic
.. clicmd:: hostname dynamic

.. index:: no hostname dynamic
.. clicmd:: no hostname dynamic

   Enable support for dynamic hostname.

.. index:: area-password [clear | md5] <password>
.. clicmd:: area-password [clear | md5] <password>

.. index:: domain-password [clear | md5] <password>
.. clicmd:: domain-password [clear | md5] <password>

.. index:: no area-password
.. clicmd:: no area-password

.. index:: no domain-password
.. clicmd:: no domain-password

   Configure the authentication password for an area, respectively a domain, as
   clear text or md5 one.

.. index:: log-adjacency-changes
.. clicmd:: log-adjacency-changes

.. index:: no log-adjacency-changes
.. clicmd:: no log-adjacency-changes

   Log changes in adjacency state.

.. index:: metric-style [narrow | transition | wide]
.. clicmd:: metric-style [narrow | transition | wide]

.. index:: no metric-style
.. clicmd:: no metric-style

   Set old-style (ISO 10589) or new-style packet formats:

   - narrow
     Use old style of TLVs with narrow metric
   - transition
     Send and accept both styles of TLVs during transition
   - wide
     Use new style of TLVs to carry wider metric

.. index:: set-overload-bit
.. clicmd:: set-overload-bit

.. index:: no set-overload-bit
.. clicmd:: no set-overload-bit

   Set overload bit to avoid any transit traffic.

.. index:: purge-originator
.. clicmd:: purge-originator

.. index:: no purge-originator
.. clicmd:: no purge-originator

   Enable or disable :rfc:`6232` purge originator identification.

.. _rift-timer:

RIFT Timer
==========

.. index:: lsp-gen-interval (1-120)
.. clicmd:: lsp-gen-interval (1-120)

.. index:: lsp-gen-interval [level-1 | level-2] (1-120)
.. clicmd:: lsp-gen-interval [level-1 | level-2] (1-120)

.. index:: no lsp-gen-interval
.. clicmd:: no lsp-gen-interval

.. index:: no lsp-gen-interval [level-1 | level-2]
.. clicmd:: no lsp-gen-interval [level-1 | level-2]

   Set minimum interval in seconds between regenerating same LSP,
   globally, for an area (level-1) or a domain (level-2).

.. index:: lsp-refresh-interval [level-1 | level-2] (1-65235)
.. clicmd:: lsp-refresh-interval [level-1 | level-2] (1-65235)

.. index:: no lsp-refresh-interval [level-1 | level-2]
.. clicmd:: no lsp-refresh-interval [level-1 | level-2]

   Set LSP refresh interval in seconds, globally, for an area (level-1) or a
   domain (level-2).

.. index:: max-lsp-lifetime (360-65535)
.. clicmd:: max-lsp-lifetime (360-65535)

.. index:: max-lsp-lifetime [level-1 | level-2] (360-65535)
.. clicmd:: max-lsp-lifetime [level-1 | level-2] (360-65535)

.. index:: no max-lsp-lifetime
.. clicmd:: no max-lsp-lifetime

.. index:: no max-lsp-lifetime [level-1 | level-2]
.. clicmd:: no max-lsp-lifetime [level-1 | level-2]

   Set LSP maximum LSP lifetime in seconds, globally, for an area (level-1) or
   a domain (level-2).

.. index:: spf-interval (1-120)
.. clicmd:: spf-interval (1-120)

.. index:: spf-interval [level-1 | level-2] (1-120)
.. clicmd:: spf-interval [level-1 | level-2] (1-120)

.. index:: no spf-interval
.. clicmd:: no spf-interval

.. index:: no spf-interval [level-1 | level-2]
.. clicmd:: no spf-interval [level-1 | level-2]

   Set minimum interval between consecutive SPF calculations in seconds.

.. _rift-region:

RIFT region
===========

.. index:: is-type [level-1 | level-1-2 | level-2-only]
.. clicmd:: is-type [level-1 | level-1-2 | level-2-only]

.. index:: no is-type
.. clicmd:: no is-type

   Define the RIFT router behavior:

   - level-1
     Act as a station router only
   - level-1-2
     Act as both a station router and an area router
   - level-2-only
     Act as an area router only

.. _rift-interface:

RIFT interface
==============

.. _ip-router-rift-word:

.. index:: [no] <ip|ipv6> router rift WORD
.. clicmd:: [no] <ip|ipv6> router rift WORD

   Activate RIFT adjacency on this interface. Note that the name of RIFT
   instance must be the same as the one used to configure the RIFT process (see
   command :clicmd:`router rift WORD`). To enable IPv4, issue ``ip router rift
   WORD``; to enable IPv6, issue ``ipv6 router rift WORD``.

.. index:: rift circuit-type [level-1 | level-1-2 | level-2]
.. clicmd:: rift circuit-type [level-1 | level-1-2 | level-2]

.. index:: no rift circuit-type
.. clicmd:: no rift circuit-type

   Configure circuit type for interface:

   - level-1
     Level-1 only adjacencies are formed
   - level-1-2
     Level-1-2 adjacencies are formed
   - level-2-only
     Level-2 only adjacencies are formed

.. index:: rift csnp-interval (1-600)
.. clicmd:: rift csnp-interval (1-600)

.. index:: rift csnp-interval (1-600) [level-1 | level-2]
.. clicmd:: rift csnp-interval (1-600) [level-1 | level-2]

.. index:: no rift csnp-interval
.. clicmd:: no rift csnp-interval

.. index:: no rift csnp-interval [level-1 | level-2]
.. clicmd:: no rift csnp-interval [level-1 | level-2]

   Set CSNP interval in seconds globally, for an area (level-1) or a domain
   (level-2).

.. index:: rift hello padding
.. clicmd:: rift hello padding

   Add padding to RIFT hello packets.

.. index:: rift hello-interval (1-600)
.. clicmd:: rift hello-interval (1-600)

.. index:: rift hello-interval (1-600) [level-1 | level-2]
.. clicmd:: rift hello-interval (1-600) [level-1 | level-2]

.. index:: no rift hello-interval
.. clicmd:: no rift hello-interval

.. index:: no rift hello-interval [level-1 | level-2]
.. clicmd:: no rift hello-interval [level-1 | level-2]

   Set Hello interval in seconds globally, for an area (level-1) or a domain
   (level-2).

.. index:: rift hello-multiplier (2-100)
.. clicmd:: rift hello-multiplier (2-100)

.. index:: rift hello-multiplier (2-100) [level-1 | level-2]
.. clicmd:: rift hello-multiplier (2-100) [level-1 | level-2]

.. index:: no rift hello-multiplier
.. clicmd:: no rift hello-multiplier

.. index:: no rift hello-multiplier [level-1 | level-2]
.. clicmd:: no rift hello-multiplier [level-1 | level-2]

   Set multiplier for Hello holding time globally, for an area (level-1) or a
   domain (level-2).

.. index:: rift metric [(0-255) | (0-16777215)]
.. clicmd:: rift metric [(0-255) | (0-16777215)]

.. index:: rift metric [(0-255) | (0-16777215)] [level-1 | level-2]
.. clicmd:: rift metric [(0-255) | (0-16777215)] [level-1 | level-2]

.. index:: no rift metric
.. clicmd:: no rift metric

.. index:: no rift metric [level-1 | level-2]
.. clicmd:: no rift metric [level-1 | level-2]

   Set default metric value globally, for an area (level-1) or a domain
   (level-2).  Max value depend if metric support narrow or wide value (see
   command :clicmd:`metric-style [narrow | transition | wide]`).

.. index:: rift network point-to-point
.. clicmd:: rift network point-to-point

.. index:: no rift network point-to-point
.. clicmd:: no rift network point-to-point

   Set network type to 'Point-to-Point' (broadcast by default).

.. index:: rift passive
.. clicmd:: rift passive

.. index:: no rift passive
.. clicmd:: no rift passive

   Configure the passive mode for this interface.

.. index:: rift password [clear | md5] <password>
.. clicmd:: rift password [clear | md5] <password>

.. index:: no rift password
.. clicmd:: no rift password

   Configure the authentication password (clear or encoded text) for the
   interface.

.. index:: rift priority (0-127)
.. clicmd:: rift priority (0-127)

.. index:: rift priority (0-127) [level-1 | level-2]
.. clicmd:: rift priority (0-127) [level-1 | level-2]

.. index:: no rift priority
.. clicmd:: no rift priority

.. index:: no rift priority [level-1 | level-2]
.. clicmd:: no rift priority [level-1 | level-2]

   Set priority for Designated Router election, globally, for the area
   (level-1) or the domain (level-2).

.. index:: rift psnp-interval (1-120)
.. clicmd:: rift psnp-interval (1-120)

.. index:: rift psnp-interval (1-120) [level-1 | level-2]
.. clicmd:: rift psnp-interval (1-120) [level-1 | level-2]

.. index:: no rift psnp-interval
.. clicmd:: no rift psnp-interval

.. index:: no rift psnp-interval [level-1 | level-2]
.. clicmd:: no rift psnp-interval [level-1 | level-2]

   Set PSNP interval in seconds globally, for an area (level-1) or a domain
   (level-2).

.. index:: rift three-way-handshake
.. clicmd:: rift three-way-handshake

.. index:: no rift three-way-handshake
.. clicmd:: no rift three-way-handshake

   Enable or disable :rfc:`5303` Three-Way Handshake for P2P adjacencies.
   Three-Way Handshake is enabled by default.

.. _showing-rift-information:

Showing RIFT information
========================

.. index:: show rift summary
.. clicmd:: show rift summary

   Show summary information about RIFT.

.. index:: show rift hostname
.. clicmd:: show rift hostname

   Show information about RIFT node.

.. index:: show rift interface
.. clicmd:: show rift interface

.. index:: show rift interface detail
.. clicmd:: show rift interface detail

.. index:: show rift interface <interface name>
.. clicmd:: show rift interface <interface name>

   Show state and configuration of RIFT specified interface, or all interfaces
   if no interface is given with or without details.

.. index:: show rift neighbor
.. clicmd:: show rift neighbor

.. index:: show rift neighbor <System Id>
.. clicmd:: show rift neighbor <System Id>

.. index:: show rift neighbor detail
.. clicmd:: show rift neighbor detail

   Show state and information of RIFT specified neighbor, or all neighbors if
   no system id is given with or without details.

.. index:: show rift database
.. clicmd:: show rift database

.. index:: show rift database [detail]
.. clicmd:: show rift database [detail]

.. index:: show rift database <LSP id> [detail]
.. clicmd:: show rift database <LSP id> [detail]

.. index:: show rift database detail <LSP id>
.. clicmd:: show rift database detail <LSP id>

   Show the RIFT database globally, for a specific LSP id without or with
   details.

.. index:: show rift topology
.. clicmd:: show rift topology

.. index:: show rift topology [level-1|level-2]
.. clicmd:: show rift topology [level-1|level-2]

   Show topology RIFT paths to Intermediate Systems, globally, in area
   (level-1) or domain (level-2).

.. index:: show ip route rift
.. clicmd:: show ip route rift

   Show the RIFT routing table, as determined by the most recent SPF
   calculation.

.. _rift-traffic-engineering:

Traffic Engineering
===================

.. index:: mpls-te on
.. clicmd:: mpls-te on

.. index:: no mpls-te
.. clicmd:: no mpls-te

   Enable Traffic Engineering LSP flooding.

.. index:: mpls-te router-address <A.B.C.D>
.. clicmd:: mpls-te router-address <A.B.C.D>

.. index:: no mpls-te router-address
.. clicmd:: no mpls-te router-address

   Configure stable IP address for MPLS-TE.

.. index:: show rift mpls-te interface
.. clicmd:: show rift mpls-te interface

.. index:: show rift mpls-te interface INTERFACE
.. clicmd:: show rift mpls-te interface INTERFACE

   Show MPLS Traffic Engineering parameters for all or specified interface.

.. index:: show rift mpls-te router
.. clicmd:: show rift mpls-te router

   Show Traffic Engineering router parameters.

.. seealso::

   :ref:`ospf-traffic-engineering`

.. _debugging-rift:

Debugging RIFT
==============

.. index:: debug rift adj-packets
.. clicmd:: debug rift adj-packets

.. index:: no debug rift adj-packets
.. clicmd:: no debug rift adj-packets

   RIFT Adjacency related packets.

.. index:: debug rift checksum-errors
.. clicmd:: debug rift checksum-errors

.. index:: no debug rift checksum-errors
.. clicmd:: no debug rift checksum-errors

   RIFT LSP checksum errors.

.. index:: debug rift events
.. clicmd:: debug rift events

.. index:: no debug rift events
.. clicmd:: no debug rift events

   RIFT Events.

.. index:: debug rift local-updates
.. clicmd:: debug rift local-updates

.. index:: no debug rift local-updates
.. clicmd:: no debug rift local-updates

   RIFT local update packets.

.. index:: debug rift packet-dump
.. clicmd:: debug rift packet-dump

.. index:: no debug rift packet-dump
.. clicmd:: no debug rift packet-dump

   RIFT packet dump.

.. index:: debug rift protocol-errors
.. clicmd:: debug rift protocol-errors

.. index:: no debug rift protocol-errors
.. clicmd:: no debug rift protocol-errors

   RIFT LSP protocol errors.

.. index:: debug rift route-events
.. clicmd:: debug rift route-events

.. index:: no debug rift route-events
.. clicmd:: no debug rift route-events

   RIFT Route related events.

.. index:: debug rift snp-packets
.. clicmd:: debug rift snp-packets

.. index:: no debug rift snp-packets
.. clicmd:: no debug rift snp-packets

   RIFT CSNP/PSNP packets.

.. index:: debug rift spf-events
.. clicmd:: debug rift spf-events

.. index:: debug rift spf-statistics
.. clicmd:: debug rift spf-statistics

.. index:: debug rift spf-triggers
.. clicmd:: debug rift spf-triggers

.. index:: no debug rift spf-events
.. clicmd:: no debug rift spf-events

.. index:: no debug rift spf-statistics
.. clicmd:: no debug rift spf-statistics

.. index:: no debug rift spf-triggers
.. clicmd:: no debug rift spf-triggers

   RIFT Shortest Path First Events, Timing and Statistic Data and triggering
   events.

.. index:: debug rift update-packets
.. clicmd:: debug rift update-packets

.. index:: no debug rift update-packets
.. clicmd:: no debug rift update-packets

   Update related packets.

.. index:: show debugging rift
.. clicmd:: show debugging rift

   Print which RIFT debug level is activate.

RIFT Configuration Examples
===========================

A simple example, with MD5 authentication enabled:

.. code-block:: frr

   !
   interface eth0
    ip router rift FOO
    rift network point-to-point
    rift circuit-type level-2-only
   !
   router rift FOO
   net 47.0023.0000.0000.0000.0000.0000.0000.1900.0004.00
    metric-style wide
    is-type level-2-only


A Traffic Engineering configuration, with Inter-ASv2 support.

First, the :file:`zebra.conf` part:

.. code-block:: frr

   hostname HOSTNAME
   password PASSWORD
   log file /var/log/zebra.log
   !
   interface eth0
    ip address 10.2.2.2/24
    link-params
     max-bw 1.25e+07
     max-rsv-bw 1.25e+06
     unrsv-bw 0 1.25e+06
     unrsv-bw 1 1.25e+06
     unrsv-bw 2 1.25e+06
     unrsv-bw 3 1.25e+06
     unrsv-bw 4 1.25e+06
     unrsv-bw 5 1.25e+06
     unrsv-bw 6 1.25e+06
     unrsv-bw 7 1.25e+06
     admin-grp 0xab
   !
   interface eth1
    ip address 10.1.1.1/24
    link-params
     enable
     metric 100
     max-bw 1.25e+07
     max-rsv-bw 1.25e+06
     unrsv-bw 0 1.25e+06
     unrsv-bw 1 1.25e+06
     unrsv-bw 2 1.25e+06
     unrsv-bw 3 1.25e+06
     unrsv-bw 4 1.25e+06
     unrsv-bw 5 1.25e+06
     unrsv-bw 6 1.25e+06
     unrsv-bw 7 1.25e+06
     neighbor 10.1.1.2 as 65000


Then the :file:`riftd.conf` itself:

.. code-block:: frr

   hostname HOSTNAME
   password PASSWORD
   log file /var/log/riftd.log
   !
   !
   interface eth0
    ip router rift FOO
   !
   interface eth1
    ip router rift FOO
   !
   !
   router rift FOO
    rift net 47.0023.0000.0000.0000.0000.0000.0000.1900.0004.00
     mpls-te on
     mpls-te router-address 10.1.1.1
   !
   line vty
