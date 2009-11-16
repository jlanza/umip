/*
 * $Id: ndisc.c 1.56 06/05/06 15:15:47+03:00 anttit@tcs.hut.fi $
 *
 * This file is part of the MIPL Mobile IPv6 for Linux.
 * 
 * Authors: Antti Tuominen <anttit@tcs.hut.fi>
 *          Ville Nuorvala <vnuorval@tcs.hut.fi>
 *
 * Copyright 2003-2005 Go-Core Project
 * Copyright 2003-2006 Helsinki University of Technology
 *
 * MIPL Mobile IPv6 for Linux is free software; you can redistribute
 * it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; version 2 of
 * the License.
 *
 * MIPL Mobile IPv6 for Linux is distributed in the hope that it will
 * be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MIPL Mobile IPv6 for Linux; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <pthread.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip6.h>
#include <netinet/ip6mh.h>
#include <libnetlink.h>

#include "debug.h"
#include "icmp6.h"
#include "tqueue.h"
#include "util.h"
#include "ndisc.h"
#include "rtnl.h"
#include "proc_sys.h"

static int neigh_mod(int nl_flags, int cmd, int ifindex,
		     uint16_t state, uint8_t flags, struct in6_addr *dst,
		     uint8_t *hwa, int hwalen)
{
	uint8_t buf[256];
	struct nlmsghdr *n;
	struct ndmsg *ndm;

	memset(buf, 0, sizeof(buf));
	n = (struct nlmsghdr *)buf;
	n->nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	n->nlmsg_flags = NLM_F_REQUEST|nl_flags;
	n->nlmsg_type = cmd;

        ndm = NLMSG_DATA(n);
	ndm->ndm_family = AF_INET6;
	ndm->ndm_ifindex = ifindex;
	ndm->ndm_state = state;
	ndm->ndm_flags = flags;
	ndm->ndm_type = (IN6_IS_ADDR_MULTICAST(dst) ? 
			 RTN_MULTICAST : RTN_UNICAST);

	addattr_l(n, sizeof(buf), NDA_DST, dst, sizeof(*dst));

	if (hwa)
		addattr_l(n, sizeof(buf), NDA_LLADDR, hwa, hwalen);

	return rtnl_route_do(n, NULL);
}

int neigh_add(int ifindex, uint16_t state, uint8_t flags,
	      struct in6_addr *dst, uint8_t *hwa, int hwalen,
	      int override)
{
	return neigh_mod(NLM_F_CREATE | (override ? NLM_F_REPLACE : 0),
			 RTM_NEWNEIGH, ifindex, state, flags,dst, hwa, hwalen);
}

int neigh_del(int ifindex, struct in6_addr *dst)
{
	return neigh_mod(0, RTM_DELNEIGH, ifindex, 0, 0, dst, NULL, 0);
}

int pneigh_add(int ifindex, uint8_t flags, struct in6_addr *dst)
{
	return neigh_mod(NLM_F_CREATE | NLM_F_REPLACE, RTM_NEWNEIGH,
			 ifindex, NUD_PERMANENT, flags|NTF_PROXY, dst,
			 NULL, 0);
}

int pneigh_del(int ifindex, struct in6_addr *dst)
{
	return neigh_mod(0, RTM_DELNEIGH, ifindex, 0, NTF_PROXY, dst, NULL, 0);
}

static inline void proxy_nd_iface_set(int ifindex, int val)
{
	char ifname[IF_NAMESIZE];

	if (if_indextoname(ifindex, ifname) != NULL)
		set_iface_proc_entry(PROC_SYS_IP6_PROXY_NDP, ifname, val);
}

void proxy_nd_iface_init(int ifindex)
{
	proxy_nd_iface_set(ifindex, 1);
}

void proxy_nd_iface_cleanup(int ifindex)
{
	proxy_nd_iface_set(ifindex, 0);
}

int proxy_nd_start(int ifindex, struct in6_addr *target, 
		   struct in6_addr *src, int bu_flags)
{
	struct in6_addr lladdr;
	int err;
	int nd_flags = bu_flags&IP6_MH_BU_MR ? NTF_ROUTER : 0;

	err = pneigh_add(ifindex, nd_flags, target);

	if (!err && bu_flags & IP6_MH_BU_LLOCAL) {
		ipv6_addr_llocal(target, &lladdr);
		err = pneigh_add(ifindex, nd_flags, &lladdr);
		if (err)
			pneigh_del(ifindex, target);
	}
	if (!err) {
		uint32_t na_flags = (ND_NA_FLAG_OVERRIDE |
				     nd_flags ? ND_NA_FLAG_ROUTER : 0);

		ndisc_send_na(ifindex, src, &in6addr_all_nodes_mc,
			      target, na_flags);

		if (bu_flags & IP6_MH_BU_LLOCAL)
			ndisc_send_na(ifindex, src, &in6addr_all_nodes_mc,
				      &lladdr, na_flags);
	}
	return err;
}

void proxy_nd_stop(int ifindex, struct in6_addr *target, int bu_flags)
{
	if (bu_flags & IP6_MH_BU_LLOCAL) {
		struct in6_addr lladdr;
		ipv6_addr_llocal(target, &lladdr);
		pneigh_del(ifindex, &lladdr);
		neigh_del(ifindex, &lladdr);
	}
	pneigh_del(ifindex, target);
	neigh_del(ifindex, target);
}

static struct nd_opt_hdr *nd_opt_create(struct iovec *iov, uint8_t type,
					uint16_t len, uint8_t *value)
{
	struct nd_opt_hdr *opt;
	int hlen = sizeof(struct nd_opt_hdr);

	/* len must be lenght(value) in bytes */
	opt = malloc(len + hlen);
	if (opt == NULL)
		return NULL;

	opt->nd_opt_type = type;
	opt->nd_opt_len = (len + hlen) >> 3;
	memcpy(opt + 1, value, len);
	iov->iov_base = opt;
	iov->iov_len = len + hlen;

	return opt;
}

static int nd_get_l2addr(int ifindex, uint8_t *addr)
{
	struct ifreq ifr;
	int fd;
	int res;
 
	fd = socket(PF_PACKET, SOCK_DGRAM, 0);
	if (fd < 0) return -1;

	memset(&ifr, 0, sizeof(ifr));
	if_indextoname(ifindex, ifr.ifr_name);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}
	if ((res = nd_get_l2addr_len(ifr.ifr_hwaddr.sa_family)) < 0)
		dbg("Unsupported sa_family %d.\n", ifr.ifr_hwaddr.sa_family);
	else if (res > 0)
		memcpy(addr, ifr.ifr_hwaddr.sa_data, res);

	close(fd);
	return res;
}

/* Linearize 'iov' of 'iovlen' elements in 'dst' buffer of available size
 * 'dstlen'. The number of bytes written to dst is returned in 'written'
 * if everything went ok. 0 is returned on success, -1 on error. */
static int iov_linearize(uint8_t *dst, int dstlen, struct iovec *iov,
			 size_t iovlen, int *written) {
	int i = 0, l;
	int rem = dstlen;
	uint8_t *data = dst;
	struct iovec cur;

	if (iov == NULL || iovlen == 0)
		return 0;

	cur = iov[i];

	while ((i < iovlen) && ((l = cur.iov_len) <= rem)) {
		if (cur.iov_base == NULL)
			return -1;

		memcpy(data, cur.iov_base, l);
		cur = iov[++i];
		rem  -= l;
		data += l;
	}

	if (i != iovlen) { /* Someone left behind? */
		dbg("Not enough space to linearize iov\n");
		return -1;
	}

	*written = dstlen - rem;

	return 0;
}

static int ndisc_send_unspec(int oif, const struct in6_addr *dest,
			     uint8_t *hdr, int hdrlen, struct iovec *optv,
			     size_t optvlen)
{
	struct {
		struct ip6_hdr ip;
		struct icmp6_hdr icmp;
		uint8_t data[1500];
	} frame;

	struct msghdr msgh;
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pinfo;
	struct sockaddr_in6 dst;
	char cbuf[CMSG_SPACE(sizeof(*pinfo))];
	struct iovec iov;
	uint8_t *data = (uint8_t *)(&frame.icmp);
	int fd, ret, remlen, datalen = 0, written = 0, v = 1;

	if (hdr == NULL || hdrlen < sizeof(struct icmp6_hdr) ||
	    hdrlen > (sizeof(frame) - sizeof(struct ip6_hdr)))
		return -EINVAL;

	if ((fd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0)
		return -1;

	if (setsockopt(fd, IPPROTO_IPV6, IP_HDRINCL, &v, sizeof(v)) < 0) {
		dbg("cannot set IP_HDRINCL: %s\n", strerror(errno));
		close(fd);
		return -errno;
	}

	memset(&frame, 0, sizeof(frame));
	memset(&dst, 0, sizeof(dst));

	dst.sin6_addr = *dest;

	/* Copy ICMPv6 header and update various length values */
	memcpy(data, hdr, hdrlen);
	data += hdrlen;
	datalen += hdrlen;
	remlen = sizeof(frame) - sizeof(struct ip6_hdr) - hdrlen;

	/* Prepare for csum: write trailing options by linearizing iov */
	if ((iov_linearize(data, remlen, optv, optvlen, &written) != 0) ||
	    (written & 0x1)) /* Ensure length is even for csum() */
		return -1;
	datalen += written;

	/* Fill in the IPv6 header */
	frame.ip.ip6_vfc = 0x60;
	frame.ip.ip6_plen = htons(datalen);
	frame.ip.ip6_nxt = IPPROTO_ICMPV6;
	frame.ip.ip6_hlim = 255;
	frame.ip.ip6_dst = *dest;
	/* all other fields are already set to zero */

	frame.icmp.icmp6_cksum = in6_cksum(&in6addr_any, dest, &frame.icmp,
					   datalen, IPPROTO_ICMPV6);

	iov.iov_base = &frame;
	iov.iov_len = sizeof(frame.ip) + datalen;

	dst.sin6_family = AF_INET6;
	msgh.msg_name = &dst;
	msgh.msg_namelen = sizeof(dst);
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_flags = 0;

	memset(cbuf, 0, CMSG_SPACE(sizeof(*pinfo)));
	cmsg = (struct cmsghdr *)cbuf;
	pinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	pinfo->ipi6_ifindex = oif;

	cmsg->cmsg_len = CMSG_LEN(sizeof(*pinfo));
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	msgh.msg_control = cmsg;
	msgh.msg_controllen = cmsg->cmsg_len;

	ret = sendmsg(fd, &msgh, 0);
	if (ret < 0)
		dbg("sendmsg: %s\n", strerror(errno));

	close(fd);
	return ret;
}

int ndisc_send_rs(int ifindex, const struct in6_addr *dst,
		  struct iovec *opts, size_t optslen)
{
	struct nd_router_solicit rs;
	uint8_t *hdr = (uint8_t *)&rs;
	int hdrlen = sizeof(rs);

	memset(hdr, 0, hdrlen);
	rs.nd_rs_type = ND_ROUTER_SOLICIT;

	return ndisc_send_unspec(ifindex, dst, hdr, hdrlen, opts, optslen);
}

int ndisc_send_ns(int ifindex, const struct in6_addr *target)
{
	struct nd_neighbor_solicit ns;
	uint8_t *hdr = (uint8_t *)&ns;
	int hdrlen = sizeof(ns);
	struct in6_addr dest;

	memset(hdr, 0, hdrlen);
	ns.nd_ns_type = ND_NEIGHBOR_SOLICIT;
	ns.nd_ns_target = *target;
	ipv6_addr_solict_mult(target, &dest);

	return ndisc_send_unspec(ifindex, &dest, hdr, hdrlen, NULL, 0);
}

int ndisc_send_na(int ifindex, const struct in6_addr *src, 
		  const struct in6_addr *dst,
		  const struct in6_addr *target, uint32_t flags)
{
	struct nd_neighbor_advert *na;
	struct iovec iov[2];
	uint8_t l2addr[32];
	int len;

	memset(iov, 0, sizeof(iov));

	if ((len = nd_get_l2addr(ifindex, l2addr)) < 0)
		return -EINVAL;

	na = icmp6_create(iov, ND_NEIGHBOR_ADVERT, 0);

	if (na == NULL) return -ENOMEM;

	if (len > 0 && nd_opt_create(&iov[1], ND_OPT_TARGET_LINKADDR,
				     len, l2addr) == NULL) {
		free_iov_data(iov, 1);
		return -ENOMEM;
	}
	na->nd_na_target = *target;
	na->nd_na_flags_reserved = flags;

	icmp6_send(ifindex, 255, src, dst, iov, 2);
	free_iov_data(iov, 2);
	return 0;
}

int ndisc_do_dad(int ifi, struct in6_addr *addr, int do_ll)
{
	struct in6_pktinfo pinfo;
	struct sockaddr_in6 saddr;
	struct nd_neighbor_advert *hdr;
	struct icmp6_filter filter;
	struct in6_addr solicit, ll;
	unsigned char msg[MAX_PKT_LEN];
	int hoplimit, sock = -1, ret, val = 1, err = -1;
	fd_set rset;
	struct timeval tv;

	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &filter);

	sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (sock < 0) {
		dbg("socket: %s\n", strerror(errno));
		goto end;
	}

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		       &val, sizeof(val)) < 0) {
		dbg("cannot set IPV6_RECVPKTINFO: %s\n", strerror(errno));
		goto end;
	}
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
		       &val, sizeof(val)) < 0) {
		dbg("cannot set IPV6_RECVHOPLIMIT: %s\n", strerror(errno));
		goto end;
	}
	if (setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
		       sizeof(struct icmp6_filter)) < 0) {
		dbg("cannot set ICMPV6_FILTER: %s\n", strerror(errno));
		goto end;
	}

	ipv6_addr_solict_mult(addr, &solicit);
	if (if_mc_group(sock, ifi, &in6addr_all_nodes_mc, IPV6_JOIN_GROUP)) {
		dbg("cannot join all node mc\n");
		goto end;
	}
	if (if_mc_group(sock, ifi, &solicit, IPV6_JOIN_GROUP)) {
		dbg("cannot joing slicit node mc\n");
		goto end;
	}
	if (ndisc_send_ns(ifi, addr) <= 0) {
		dbg("Error at sending NS\n");
		goto end;
	}

	if (do_ll) {
		ipv6_addr_llocal(addr, &ll);
		if (ndisc_send_ns(ifi, &ll) <= 0) {
			dbg("Error at sending NS (link-local target)\n");
			goto end;
		}
	}

	FD_ZERO(&rset);
	FD_SET(sock, &rset);
	tv.tv_sec = DAD_TIMEOUT;
	tv.tv_usec = 0;
	for (;;) {
		/* Note on portability: we assume that tv is modified to show
		   the time left which is AFAIK true only in Linux 
		   timeout 
		*/
		if (select(sock+1, &rset, NULL, NULL, &tv) == 0) {
			dbg("Dad success\n");
			err = 0;
			break;
		}
		if (!FD_ISSET(sock, &rset))
			continue;
		/* We got an ICMPv6 packet */
		ret = icmp6_recv(sock, msg, sizeof(msg), &saddr, 
				 &pinfo, &hoplimit);
		if (ret < 0)
			continue;
		hdr = (struct nd_neighbor_advert *)msg;
		if (hdr->nd_na_code != 0)
			continue;
		if (IN6_ARE_ADDR_EQUAL(addr, &hdr->nd_na_target) ||
		    (do_ll && IN6_ARE_ADDR_EQUAL(&ll, &hdr->nd_na_target))) {
			dbg("Failure\n");
			break;
		}
	}
 end:
	if (sock >= 0)
		close(sock);
	return err;
}
