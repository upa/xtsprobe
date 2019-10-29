/* xtsprobe.c */

/*
 * End.XTS

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Next Header   |  Hdr Ext Len  | Routing Type  | Segments Left |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Last Entry   |     Flags     |              Tag              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |            Segment List[0] (128 bits IPv6 address)            |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                                                               |
                                  ...
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |            Segment List[n] (128 bits IPv6 address)            |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //                                                             //
    //         Optional Type Length Value objects (variable)       //
    //                                                             //
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Desitnation Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Length             |           Checksum            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                  SID[0] (128 bits IPv6 address)               |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        SL[0]  Second                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        SL[0]  Nanoecond                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //                                                             //
    //                SID(s) and struct timespec(s)                //
    //                                                             //
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                  SID[n] (128 bits IPv6 address)               |
    |                                                               |
    |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        SL[n]  Second                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        SL[n]  Nanoecond                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/* xtsprobe sends probe packet(s) that includes SRv6 and UDP headers
 * through raw socket, and receives the UDP probe packets (SRH is
 * popped). Thus, this requires PSP on paths where the packets are
 * steered.
 */



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/errqueue.h>

#define MAX_SEGS	128
#define XTSPROBE_PORT	60001

#define pr_info(fmt, ...) fprintf(stdout, "%s: " fmt,		\
                                  __func__, ##__VA_ARGS__)

#define pr_err(fmt, ...) fprintf(stderr, "%s: " fmt,		\
                                 __func__, ##__VA_ARGS__)


/* structure contained on UDP playoad of End.XTS */
struct sr6_xts {
	struct in6_addr sid;
	struct timespec tstamp;
};


int create_raw_sock(void)
{
	int fd;
	int v = 1;

	fd = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
	if (fd < 0) {
		pr_err("failed to create raw socket: %s\n", strerror(errno));
		exit(1);
	}

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_HDRINCL, &v, sizeof(v)) < 0) {
		pr_err("failed to setup raw socket: %s\n", strerror(errno));
		exit(1);
	}

	return fd;
}

int create_udp_sock(void)
{
 	int fd;
	struct sockaddr_in6 in6;

	fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		pr_err("failed to create udp socket: %s\n", strerror(errno));
		exit(1);
	}

	memset(&in6, 0, sizeof(in6));
	in6.sin6_family = AF_INET6;
	in6.sin6_port = htons(XTSPROBE_PORT);

	if (bind(fd, (struct sockaddr *)&in6, sizeof(in6)) < 0) {
		pr_err("failed to bind udp socket: %s\n", strerror(errno));
		exit (1);
	}

	return fd;
}

int send_probe(int fd, struct in6_addr *segments, int nsegs,
	       struct in6_addr src)
{
	int ret, size, n;
	struct ip6_hdr ip6;
	struct ipv6_sr_hdr srh;
	struct in6_addr sl[MAX_SEGS];
	struct udphdr udp;
	char payload[1024];
	struct iovec iov[5];
	struct msghdr msg;
	struct sockaddr_in6 in6;
	
	size = (sizeof(struct ip6_hdr) +
		sizeof(struct ipv6_sr_hdr) +
		sizeof(struct in6_addr) * nsegs +
		sizeof(struct udphdr) +
		sizeof(struct sr6_xts) * nsegs);

	/* build IPv6 hdr */
	memset(&ip6, 0, sizeof(ip6));
	ip6.ip6_vfc = 6 << 4;
	ip6.ip6_plen = htons(size - sizeof(struct ip6_hdr));
	ip6.ip6_hlim = 255;
	ip6.ip6_src = src;
	ip6.ip6_dst = segments[0];
	ip6.ip6_nxt = IPPROTO_ROUTING;
	
	/* build SRH */
	memset(&srh, 0, sizeof(srh));
	srh.nexthdr = IPPROTO_UDP;
	srh.hdrlen = ((sizeof(struct ipv6_sr_hdr) - 8 +
		       sizeof(struct in6_addr) * nsegs) >> 3);
	srh.type = IPV6_SRCRT_TYPE_4;
	srh.segments_left = nsegs - 1;
	srh.first_segment = nsegs - 1;
	srh.tag = htons(0);

	/* build segment list */
	for (n = 0; n < nsegs; n++) {
		sl[nsegs - 1 - n] = segments[n];
	}

	/* build UDP */
	udp.source = htons(XTSPROBE_PORT);
	udp.dest = htons(XTSPROBE_PORT);
	udp.len = htons(sizeof(struct udphdr) +
			sizeof(struct sr6_xts) * nsegs);
	udp.check = 0;

	/* prepare packet for xmit */
	memset(&in6, 0, sizeof(in6));
	in6.sin6_family = AF_INET6;
	in6.sin6_addr = segments[0];

	iov[0].iov_base = &ip6;
	iov[0].iov_len = sizeof(ip6);
	iov[1].iov_base = &srh;
	iov[1].iov_len = sizeof(srh);
	iov[2].iov_base = sl;
	iov[2].iov_len = sizeof(struct in6_addr) * nsegs;
	iov[3].iov_base = &udp;
	iov[3].iov_len = sizeof(udp);
	iov[4].iov_base = payload;
	iov[4].iov_len = sizeof(struct sr6_xts) * nsegs;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 5;
	msg.msg_name = &in6;
	msg.msg_namelen = sizeof(in6);

	/* xmit */
	ret = sendmsg(fd, &msg, 0);

	return ret;
}

void print_probe(struct sr6_xts *xts, int nsegs)
{
	int n;

	for (n = nsegs - 1; n >= 0; n--) {
		char addr[64];
		inet_ntop(AF_INET6, &xts[n].sid, addr, sizeof(addr));
		printf("[%d]\t%s\t%ld.%ld\n", nsegs - n, addr,
		       xts[n].tstamp.tv_sec, xts[n].tstamp.tv_nsec);
	}
}

int recv_probe(int fd, int timeout)
{
	int ret, nsegs;
	char buf[2048];
	struct iovec iov;
	struct msghdr msg;
	struct pollfd x[1] = { { .fd = fd, .events = POLLIN, } };

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (poll(x, 1, timeout) < 0) {
		pr_err("poll failed: %s\n", strerror(errno));
		return -1;
	}

	if (!x[0].revents & POLLIN) {
		printf("Timeout\n");
		return 0;
	}

	ret = recvmsg(fd, &msg, MSG_DONTWAIT);
	if (ret % sizeof(struct sr6_xts) != 0) {
		pr_err("invalid recv len: %d\n", ret);
		return -1;
	}

	nsegs = ret / sizeof(struct sr6_xts);
	print_probe((struct sr6_xts *)buf, nsegs);

	return ret;
}

void usage(void)
{
	printf("usage: xtsprobe\n"
	       "    -s SID list\n"
	       "    -S source address\n"
	       "    -c count, 0 means infinite, default 0\n"
	       "    -t timeout (sec)\n"
	       "    -i interval (sec)\n"
	       "\n");
}
   
int main(int argc, char **argv)
{
	int ch, ret, n;
	int nsegs = 0;
	struct in6_addr segments[MAX_SEGS];
	struct in6_addr src = IN6ADDR_ANY_INIT;
	int count = 0;
	int timeout = 1000;	/* msec for poll() */
	int interval = 1000000;	/* usec for usleep() */

	int raw_sock;
	int udp_sock;

	while ((ch = getopt(argc, argv, "s:S:c:t:i:")) != -1) {
		switch (ch) {
		case 's':
			ret = inet_pton(AF_INET6, optarg, &segments[nsegs++]);
			if (ret < 1) {
				printf("invalid segment: %s\n",
				       strerror(errno));
				return -1;
			}
			break;
		case 'S':
			ret = inet_pton(AF_INET6, optarg, &src);
			if (ret < 1) {
				printf("invalid src: %s\n", strerror(errno));
				return -1;
			}
			break;
		case 'c':
			count = atoi(optarg);
			break;
		case 't':
 			timeout = (int)(atof(optarg) * 1000);
			break;
		case 'i':
			interval = (int)(atof(optarg) * 1000000);
			break;
		}
	}

	raw_sock = create_raw_sock();
	udp_sock = create_udp_sock();

	for (n = 0; n < nsegs; n++) {
		char buf[64];
		inet_ntop(AF_INET6, &segments[n], buf, sizeof(buf));
		printf("[%d] %s\n", n, buf);
	}

	while (1) {
		long elapsed;
		struct timeval start, end;

		gettimeofday(&start, NULL);
		ret = send_probe(raw_sock, segments, nsegs, src);
		if (ret < 0) {
			gettimeofday(&end, NULL);
			pr_err("send failed: %s\n", strerror(errno));
			goto next;
		}

		ret = recv_probe(udp_sock, timeout);
		gettimeofday(&end, NULL);

		if (count > 0) {
			count--;
			if (count == 0)
				break;
		}

		elapsed = ((end.tv_sec * 1000000 + end.tv_usec) -
			   (start.tv_sec * 1000000 + start.tv_usec));

	next:
		if (elapsed < interval)
			usleep(interval - elapsed);
 	}

	close(raw_sock);

	return 0;
}
