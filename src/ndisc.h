/* $Id: ndisc.h 1.13 04/09/20 12:47:39+03:00 vnuorval@tcs.hut.fi $ */

#ifndef __NDISC_H__
#define __NDISC_H__ 1

#include <net/if_arp.h>

#define DAD_TIMEOUT 1 /* one second */

static inline short nd_get_l2addr_len(unsigned short iface_type)
{
	switch (iface_type) {
		/* supported physical devices */
	case ARPHRD_ETHER:
	case ARPHRD_IEEE802:
	case ARPHRD_IEEE802_TR:
	case ARPHRD_IEEE80211:
	case ARPHRD_FDDI:
		return 6;
		/* supported virtual devices */
	case ARPHRD_SIT:
	case ARPHRD_TUNNEL6:
	case ARPHRD_PPP:
	case ARPHRD_IPGRE:
		return 0;
	default:
		/* unsupported */
		return -1;
	}
}

/* Based on iface type (iface_type) and associated link-layer
 * address (hwa), the function generates the modified eui-64
 * and fills lladdr with associated link-layer address base
 * on that interface identifier.
 * The function returns 0 on success, -EINVAL on error. */
static inline int ndisc_set_linklocal(struct in6_addr *lladdr, uint8_t *hwa,
				      unsigned short iface_type)
{
	memset(lladdr, 0, sizeof(struct in6_addr));
	uint8_t *eui = lladdr->s6_addr + 8;

	switch (iface_type) {
	case ARPHRD_ETHER:
	case ARPHRD_IEEE802:
	case ARPHRD_IEEE802_TR:
	case ARPHRD_IEEE80211:
	case ARPHRD_FDDI:
		memcpy(eui, hwa, 3);
		memcpy(eui + 5, hwa + 3, 3);
		eui[0] ^= 2;
		eui[3] = 0xff;
		eui[4] = 0xfe;
		break;
	default:
		return -EINVAL;
	}
	lladdr->s6_addr[0] = 0xfe;
	lladdr->s6_addr[1] = 0x80;

	return 0;
}

int ndisc_do_dad(int ifi, struct in6_addr *addr, int ll);

int ndisc_send_rs(int ifindex, const struct in6_addr *dst);

int ndisc_send_ns(int ifindex, const struct in6_addr *target);

int ndisc_send_na(int ifindex, const struct in6_addr *src, 
		  const struct in6_addr *dst,
		  const struct in6_addr *target, uint32_t flags);

void proxy_nd_iface_init(int ifindex);

void proxy_nd_iface_cleanup(int ifindex);

int proxy_nd_start(int ifindex, struct in6_addr *target, 
		   struct in6_addr *src, int bu_flags);

void proxy_nd_stop(int ifindex, struct in6_addr *target, int bu_flags);

int neigh_add(int ifindex, uint16_t state, uint8_t flags,
	      struct in6_addr *dst, uint8_t *hwa, int hwalen,
	      int override);

int neigh_del(int ifindex, struct in6_addr *dst);

int pneigh_add(int ifindex, uint8_t flags, struct in6_addr *dst);

int pneigh_del(int ifindex, struct in6_addr *dst);


#endif
