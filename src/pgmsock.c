/*
 * Copyright (c) 2013-2015, Dalian Futures Information Technology Co., Ltd.
 *
 * Xiaoye Meng <mengxiaoye at dce dot com dot cn>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "logger.h"
#include "pgmsock.h"

pgm_sock_t *pgmsock_create(const char *network, int port, int type) {
	struct pgm_addrinfo_t *res = NULL;
	pgm_error_t *pgm_err = NULL;
	sa_family_t sa_family = AF_UNSPEC;
	pgm_sock_t *pgmsock = NULL;
	const int no_router_assist = 0;
	const int is_abort_on_reset = 0;
	const int max_tpdu = 8192;
	struct pgm_sockaddr_t addr;
	struct pgm_interface_req_t if_req;
	unsigned i = 0;
	const int multicast_loop = 1;
	const int multicast_hops = 16;
	const int dscp = 0x2e << 2;
	const int blocking = 0;

	/* parse network parameter */
	if (!pgm_getaddrinfo(network, NULL, &res, &pgm_err)) {
		xcb_log(XCB_LOG_WARNING, "Parsing network parameter: %s", pgm_err->message);
		goto err;
	}
	sa_family = res->ai_send_addrs[0].gsr_group.ss_family;
	if (!pgm_socket(&pgmsock, sa_family, SOCK_SEQPACKET, IPPROTO_PGM, &pgm_err)) {
		xcb_log(XCB_LOG_WARNING, "Creating PGM/IP socket: %s", pgm_err->message);
		goto err;
	}
	/* use RFC 2113 tagging for PGM router assist */
	pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_IP_ROUTER_ALERT,
		&no_router_assist, sizeof no_router_assist);
	/* pgm_drop_superuser(); */
	/* FIXME: set PGM parameters */
	pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_ABORT_ON_RESET, &is_abort_on_reset, sizeof is_abort_on_reset);
	pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_MTU, &max_tpdu, sizeof max_tpdu);
	if (type == PGMSOCK_SENDER) {
		const int send_only = 1;
		const int sqns = 100;
		const int max_rte = 400 * 1000;
		const int ambient_spm = pgm_secs(30);
		const int heartbeat_spm[] = {
			pgm_msecs(100),
			pgm_msecs(100),
			pgm_msecs(100),
			pgm_msecs(100),
			pgm_msecs(1300),
			pgm_secs(7),
			pgm_secs(16),
			pgm_secs(25),
			pgm_secs(30)
		};

		pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_SEND_ONLY, &send_only, sizeof send_only);
		pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_TXW_SQNS, &sqns, sizeof sqns);
		pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_TXW_MAX_RTE, &max_rte, sizeof max_rte);
		pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_AMBIENT_SPM, &ambient_spm, sizeof ambient_spm);
		pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_HEARTBEAT_SPM, &heartbeat_spm, sizeof heartbeat_spm);
	} else if (type == PGMSOCK_RECEIVER) {
		const int recv_only = 1;
		const int passive = 0;
		const int sqns = 100;
		const int peer_expiry = pgm_secs(300);
		const int spmr_expiry = pgm_msecs(25);
		const int nak_bo_ivl = pgm_msecs(50);
		const int nak_rpt_ivl = pgm_msecs(200);
		const int nak_rdata_ivl = pgm_msecs(200);
		const int nak_data_retries = 50;
		const int nak_ncf_retries = 50;

		pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_RECV_ONLY, &recv_only, sizeof recv_only);
		pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_PASSIVE, &passive, sizeof passive);
		pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_RXW_SQNS, &sqns, sizeof sqns);
		pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_PEER_EXPIRY, &peer_expiry, sizeof peer_expiry);
		pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_SPMR_EXPIRY, &spmr_expiry, sizeof spmr_expiry);
		pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_NAK_BO_IVL, &nak_bo_ivl, sizeof nak_bo_ivl);
		pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_NAK_RPT_IVL, &nak_rpt_ivl, sizeof nak_rpt_ivl);
		pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_NAK_RDATA_IVL, &nak_rdata_ivl, sizeof nak_rdata_ivl);
		pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_NAK_DATA_RETRIES,
			&nak_data_retries, sizeof nak_data_retries);
		pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_NAK_NCF_RETRIES,
			&nak_ncf_retries, sizeof nak_ncf_retries);
	} else
		goto err;
	/* create global session identifier */
	memset(&addr, '\0', sizeof addr);
	addr.sa_port = port;
	addr.sa_addr.sport = DEFAULT_DATA_SOURCE_PORT;
	if (!pgm_gsi_create_from_hostname(&addr.sa_addr.gsi, &pgm_err)) {
		xcb_log(XCB_LOG_WARNING, "Creating GSI: %s", pgm_err->message);
		goto err;
	}
	/* FIXME: assign socket to specified address */
	memset(&if_req, 0, sizeof if_req);
	if_req.ir_interface = res->ai_recv_addrs[0].gsr_interface;
	if_req.ir_scope_id  = 0;
	if (!pgm_bind3(pgmsock, &addr, sizeof addr,
		&if_req, sizeof if_req, &if_req, sizeof if_req, &pgm_err)) {
		xcb_log(XCB_LOG_WARNING, "Binding PGM socket: %s", pgm_err->message);
		goto err;
	}
	/* join IP multicast groups */
	for (; i < res->ai_recv_addrs_len; ++i)
		pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_JOIN_GROUP,
			&res->ai_recv_addrs[i], sizeof (struct group_req));
	pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_SEND_GROUP,
		&res->ai_send_addrs[0], sizeof (struct group_req));
	pgm_freeaddrinfo(res);
	/* FIXME: set IP parameters */
	pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_MULTICAST_LOOP, &multicast_loop, sizeof multicast_loop);
	pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_MULTICAST_HOPS, &multicast_hops, sizeof multicast_hops);
	pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_TOS, &dscp, sizeof dscp);
	pgm_setsockopt(pgmsock, IPPROTO_PGM, PGM_NOBLOCK, &blocking, sizeof blocking);
	if (!pgm_connect(pgmsock, &pgm_err)) {
		xcb_log(XCB_LOG_WARNING, "Connecting PGM socket: %s", pgm_err->message);
		goto err;
	}
	/*
	if (type == PGMSOCK_RECEIVER) {
		int max_tsdu = 0;
		socklen_t optlen = sizeof max_tsdu;

		pgm_getsockopt(pgmsock, IPPROTO_PGM, PGM_MSS, &max_tsdu, &optlen);
		xcb_log(XCB_LOG_NOTICE, "Max TSDU size is %d", max_tsdu);
	}
	*/
	return pgmsock;

err:
	if (res)
		pgm_freeaddrinfo(res);
	if (pgm_err)
		pgm_error_free(pgm_err);
	if (pgmsock)
		pgm_close(pgmsock, FALSE);
	return NULL;
}

inline void pgmsock_destroy(pgm_sock_t *pgmsock) {
	pgm_close(pgmsock, TRUE);
}

