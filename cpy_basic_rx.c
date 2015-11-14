/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_mempool.h>
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>

#ifdef __GCC__
#define RTE_BE_TO_CPU_16(be_16_v)  rte_be_to_cpu_16((be_16_v))
#define RTE_CPU_TO_BE_16(cpu_16_v) rte_cpu_to_be_16((cpu_16_v))
#else
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
#define RTE_BE_TO_CPU_16(be_16_v)  (be_16_v)
#define RTE_CPU_TO_BE_16(cpu_16_v) (cpu_16_v)
#else
#define RTE_BE_TO_CPU_16(be_16_v) \
        (uint16_t) ((((be_16_v) & 0xFF) << 8) | ((be_16_v) >> 8))
#define RTE_CPU_TO_BE_16(cpu_16_v) \
        (uint16_t) ((((cpu_16_v) & 0xFF) << 8) | ((cpu_16_v) >> 8))
#endif
#endif /* __GCC__ */

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 1 

#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)

struct __attribute__((__packed__)) fs_ethhdr
{
//        struct ftp_header_format ftp_header;    //5 bytes
        uint16_t src_id;                        //2 bytes
        uint16_t dest_id;                       //2 bytes
        uint16_t eth_type;                      //2 bytes
        uint16_t ctrl;                          //2 byte
        uint32_t seq_no;                        //4 bytes
        uint8_t proto;                          //1 byte
        uint8_t port;                           //1 byte
};

char payload[1486];

#if 1
static int create_packet(uint8_t *buffer,uint32_t sq_num, uint8_t ctl_num){
	sq_num=100;
	ctl_num=4;
	int i=0;
        memset(buffer,0,1500);
        struct fs_ethhdr *new_eth_hdr = (struct fs_ethhdr *)buffer;
      //  size_t MSG_SIZE = ETH_FRAME_SIZE-ETH_HLEN;
        new_eth_hdr->proto = 0x0a;
        new_eth_hdr->port = 10;
        new_eth_hdr->dest_id = htons(23);
        new_eth_hdr->src_id = htons(2);
        new_eth_hdr->seq_no = htonl(0x02000000 | sq_num);
        new_eth_hdr->ctrl = htons(ctl_num);
        new_eth_hdr->eth_type = 0x0101;
	for(i=0;i<1486;i++){
	 *(buffer+sizeof(struct fs_ethhdr)+i)='A'+i;
	}
	return 0;
      //  return MSG_SIZE;
}
#endif

static inline struct rte_mbuf *
tx_mbuf_alloc(struct rte_mempool *mp)
{
        struct rte_mbuf *m;

        m = __rte_mbuf_raw_alloc(mp);
        __rte_mbuf_sanity_check_raw(m, 0);
        return (m);
}

static inline uint16_t
ip_sum(const unaligned_uint16_t *hdr, int hdr_len)
{
        uint32_t sum = 0;

        while (hdr_len > 1)
        {
                sum += *hdr++;
                if (sum & 0x80000000)
                        sum = (sum & 0xFFFF) + (sum >> 16);
                hdr_len -= 2;
        }

        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);

        return ~sum;
}

//static unsigned cfg_n_flows     = 1024;
//static unsigned cfg_pkt_size    = 300;
//static uint32_t cfg_ip_src      = IPv4(10, 254, 0, 0);
//static uint32_t cfg_ip_dst      = IPv4(10,1,2,2);
//static uint16_t cfg_udp_src     = 1000;
//static uint16_t cfg_udp_dst     = 1001;
//static struct ether_addr cfg_ether_src  =
//        {{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x00 }};
//static struct ether_addr cfg_ether_dst  =
//        {{ 0xa, 0xb, 0xf, 0xc, 0xd, 0xc }};


static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

struct rte_mempool *mbuf_pool;
/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static void lcore_main(void)
{
	const uint8_t nb_ports = rte_eth_dev_count();
	uint8_t port;
//	int32_t num_packets=10000;
//	int i=0;
	//uint8_t *data=NULL;
	struct rte_mbuf *bufs[BURST_SIZE];
//	struct rte_mbuf* pkt;
//	struct ether_hdr* eth_hdr=NULL;
//	struct ipv4_hdr* ip_hdr=NULL;
//	struct udp_hdr *udp_hdr=NULL;
 //       pkt=tx_mbuf_alloc(mbuf_pool);
//	bufs[0]=pkt;
	uint8_t buffer[1500];
//	char data_send[10]={'1','2','3','4','5','6','7','8','9','A'};
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());
	create_packet(buffer,1,34);
/************************* Create Packet********************************/
//		int pkt_size= 1500;//sizeof(*ip_hdr)+sizeof(*eth_hdr)+sizeof(udp_hdr)+10;
//		pkt->data_len = pkt_size;
//               pkt->next = NULL;
//        	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
#if 0
                ether_addr_copy(&cfg_ether_dst, &eth_hdr->d_addr);
                ether_addr_copy(&cfg_ether_src, &eth_hdr->s_addr);
                eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

                /* Initialize IP header. */
                ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
                memset(ip_hdr, 0, sizeof(*ip_hdr));
                ip_hdr->version_ihl     = IP_VHL_DEF;
                ip_hdr->type_of_service = 0;
                ip_hdr->fragment_offset = 0;
                ip_hdr->time_to_live    = IP_DEFTTL;
                ip_hdr->next_proto_id   = IPPROTO_UDP;
                ip_hdr->packet_id       = 0;
                ip_hdr->src_addr        = rte_cpu_to_be_32(cfg_ip_src);
                ip_hdr->dst_addr        = rte_cpu_to_be_32(cfg_ip_dst);
                ip_hdr->total_length    = RTE_CPU_TO_BE_16(pkt_size -
                                                           sizeof(*eth_hdr));
                ip_hdr->hdr_checksum    = ip_sum((unaligned_uint16_t *)ip_hdr,
                                                 sizeof(*ip_hdr));

                /* Initialize UDP header. */
                udp_hdr = (struct udp_hdr *)(ip_hdr + 1);
                udp_hdr->src_port       = rte_cpu_to_be_16(cfg_udp_src);
                udp_hdr->dst_port       = rte_cpu_to_be_16(cfg_udp_dst);
                udp_hdr->dgram_cksum    = 0; /* No UDP checksum. */
                udp_hdr->dgram_len      = RTE_CPU_TO_BE_16(pkt_size -
                                                           sizeof(*eth_hdr) -
     
                                                      sizeof(*ip_hdr));
#endif
		//data=(uint8_t*)(udp_+1);
//		memcpy(eth_hdr,buffer,1500);
//                pkt->nb_segs            = 1;
//                pkt->pkt_len            = pkt_size;
//                pkt->ol_flags           = 0;
//                pkt->vlan_tci           = 0;//vlan_tci;
//                pkt->vlan_tci_outer     = 0;//vlan_tci_outer;
//                pkt->l2_len             = sizeof(struct ether_hdr);
//                pkt->l3_len             = sizeof(struct ipv4_hdr);
             //   pkts_burst[nb_pkt]      = pkt;

/*******************************************************************************/
	/* Run until the application is quit or killed. */
//	uint16_t total_rx =0;
	printf("About to receive packet\n");
	port=0;
//	uint16_t nb_rx=0;
#if 0
	uint16_t buf;

	port = 0;
	do{
		if((nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE)))
		{
			total_rx = total_rx + nb_rx;
			for(buf = 0; buf < nb_rx; buf++)
				rte_pktmbuf_free(bufs[buf]);
			printf("Received: %d \n",total_rx);

		}
	}while(1);

	printf("Do not cross\n");
#endif



	while(1){

		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
#if 0
		for (port = 0; port < nb_ports; port++) {

		}
#endif
		/* Get burst of RX packets, from first port of pair. */
                        const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
                                        bufs, BURST_SIZE);

                        if (unlikely(nb_rx == 0))
                                continue;

                        /* Send burst of TX packets, to second port of pair. */
                        const uint16_t nb_tx = rte_eth_tx_burst(port, 0,
                                        bufs, nb_rx);

                        /* Free any unsent packets. */
                        if (unlikely(nb_tx < nb_rx)) {
                                uint16_t buf;
                                for (buf = nb_tx; buf < nb_rx; buf++)
                                        rte_pktmbuf_free(bufs[buf]);

			}
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	unsigned nb_ports;
	uint8_t portid;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count();
//	if (nb_ports < 2 || (nb_ports & 1))
//		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	lcore_main();

	return 0;
}
