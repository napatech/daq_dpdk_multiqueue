/*
** Copyright (C) 2016
**     University of Science and Technology of China.  All rights reserved.
** Author: Tiwei Bie <btw () mail ustc edu cn>
**         Jiaxin Liu <jiaxin10 () mail ustc edu cn>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
** Mar 2017 - Napatech A/S - fc@napatech.com
** Added support for DPDK 16.07 and Snort 3.0 with multiple packet processing
** threads with the option to use DPDK multi-queue splitting (RSS).
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <daq_api.h>
#include <sfbpf.h>
#include <sfbpf_dlt.h>

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>

#define DAQ_DPDK_VERSION 16.07

#define MBUF_CACHE_SIZE 250
#define MAX_ARGS 64

#define USE_RX_TX_LOCKING
#define DEBUG_SHOW_LOCAL_STATISTICS

#ifdef BATCH_AWARE
#define RX_RING_SIZE 128
#define TX_RING_SIZE 128
#define NUM_MBUFS 4096
#define BURST_SIZE 32
#define MBUF_PKT_SIZE  10000 + RTE_PKTMBUF_HEADROOM
#else
#define RX_RING_SIZE 256
#define TX_RING_SIZE 256
#define NUM_MBUFS 8192
#define BURST_SIZE 32
#define MBUF_PKT_SIZE  RTE_MBUF_DEFAULT_BUF_SIZE
#endif

#define MODULUS(a,b) (b)?(a % b):0

#define TAKE_LOCK(lck) \
		{int _rval; do {_rval = rte_atomic16_cmpset(lck, 0, 1);} while (unlikely(_rval == 0));}

#define RELEASE_LOCK(lck) \
        *(lck) = 0;

#define MAX_PORTS 16
static volatile uint16_t port_lock[MAX_PORTS+1];


static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = ETHER_MAX_LEN,
        .split_hdr_size = 0,
        .header_split   = 0, /* Header Split disabled */
        .hw_ip_checksum = 0, /* IP checksum offload disabled */
        .hw_vlan_filter = 0, /* VLAN filtering disabled */
        .jumbo_frame    = 0, /* Jumbo Frame Support disabled */
        .hw_strip_crc   = 0,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP,
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};


#define MAX_DPDK_DEVICES  MAX_PORTS
#define MAX_RX_QUEUES  64
#define MAX_TX_QUEUES  64


/* Device equals a single dpdk device, which may
 * have multiple queues
 */
typedef struct _dpdk_device
{
    struct rte_mempool *mbuf_pool[MAX_RX_QUEUES];
#define DPDKINST_STARTED       0x1
    uint32_t flags;
    uint16_t max_rx_queues;
    uint16_t max_tx_queues;
    uint16_t num_rx_queues;
    uint16_t num_tx_queues;
    uint8_t port;
    int index;
    int ref_cnt;
    pthread_t tid;

#ifdef DEBUG_SHOW_LOCAL_STATISTICS
	uint64_t rx_pkts[MAX_RX_QUEUES];
	uint64_t tx_pkts[MAX_TX_QUEUES];
#endif
} DpdkDevice;

static DpdkDevice *dpdk_devices[MAX_DPDK_DEVICES];
static int num_dpdk_devices;

typedef struct _dpdk_link {
	DpdkDevice *dev;
	uint16_t rx_queue;
	uint16_t tx_queue;

#ifdef DEBUG_SHOW_LOCAL_STATISTICS
	uint64_t rx_pkts;
	uint64_t tx_pkts;
#endif
} DpdkLink;

 /*
  *  Interface is either a single port (dpdk0) or dual
  *  ports for bidirectional inline mode (dpdk0:dpdk1)
  */
typedef struct _dpdk_interface
{
    char *descr;
    char *filter;
    int snaplen;
    int timeout;
    int debug;

#define DEV_IDX 0
#define PEER_IDX 1
#define LINK_NUM_DEVS 2
    DpdkLink link[LINK_NUM_DEVS];

    struct sfbpf_program fcode;
    volatile int break_loop;
    int promisc_flag;
    DAQ_Stats_t stats;
    DAQ_State state;
    char errbuf[256];
#ifdef DEBUG_SHOW_LOCAL_STATISTICS
    struct _dpdk_interface *next;
#endif
} Dpdk_Interface_t;

#ifdef DEBUG_SHOW_LOCAL_STATISTICS
static Dpdk_Interface_t *base_intf;
#endif

#ifdef USE_RX_TX_LOCKING
static pthread_mutex_t rx_mutex[MAX_DPDK_DEVICES][MAX_RX_QUEUES];
static pthread_mutex_t tx_mutex[MAX_DPDK_DEVICES][MAX_TX_QUEUES];
#endif

static void dpdk_daq_reset_stats(void *handle);


/*
 * before start of device, number of queues (rx and tx) must have been calculated
 */
static int start_device(Dpdk_Interface_t *dpdk_intf, DpdkDevice *device)
{
    struct rte_eth_conf port_conf = port_conf_default;
    int port, queue, ret;
    uint16_t rx_queues, tx_queues, i;

    port = device->port;

    TAKE_LOCK(&port_lock[port]);

    /* Same thread as the device creator must start the device */
    if ((device->flags & DPDKINST_STARTED) || device->tid != pthread_self())
    {
        int loop = 0;
        RELEASE_LOCK(&port_lock[port]);
        while (!(device->flags & DPDKINST_STARTED) && loop < 20000) {
            usleep(100);
            loop++;
        }
        return (device->flags & DPDKINST_STARTED)?DAQ_SUCCESS:DAQ_ERROR;
    }

#ifdef USE_RX_TX_LOCKING
    for (i = 0; i < MAX_RX_QUEUES; i++)
        pthread_mutex_init(&rx_mutex[port][i],NULL);

    for (i = 0; i < MAX_TX_QUEUES; i++)
        pthread_mutex_init(&tx_mutex[port][i],NULL);
#endif

    if (dpdk_intf->debug)
    {
        printf("[%lx] DPDK Start device %s on port %i - with number of rx queues %i and tx queues %i\n", pthread_self(),
                dpdk_intf->descr, port, device->num_rx_queues, device->num_tx_queues);
    }

	rx_queues = RTE_MIN(device->num_rx_queues, device->max_rx_queues);
	tx_queues = RTE_MIN(device->num_tx_queues, device->max_tx_queues);

	if (rx_queues <= 1)
		port_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;

	ret = rte_eth_dev_configure(port, rx_queues, tx_queues, &port_conf);
    if (ret != 0)
    {
        DPE(dpdk_intf->errbuf, "%s: Couldn't configure port %d\n", __FUNCTION__, port);
        goto err;
    }

    for (queue = 0; queue < rx_queues; queue++)
    {
    	if (dpdk_intf->debug)
    		printf("Setup DPDK Rx queue %i on port %i\n", queue, port);
        ret = rte_eth_rx_queue_setup(port, queue, RX_RING_SIZE,
                rte_eth_dev_socket_id(port),
                NULL, device->mbuf_pool[queue]);
        if (ret != 0)
        {
            DPE(dpdk_intf->errbuf, "%s: Couldn't setup rx queue %d for port %d\n", __FUNCTION__, queue, port);
            goto err;
        }
    }

    for (queue = 0; queue < tx_queues; queue++)
    {
    	if (dpdk_intf->debug)
    	    printf("Setup DPDK Tx queue %i on port %i\n", queue, port);
        ret = rte_eth_tx_queue_setup(port, queue, TX_RING_SIZE,
                rte_eth_dev_socket_id(port),
                NULL);
        if (ret != 0)
        {
            DPE(dpdk_intf->errbuf, "%s: Couldn't setup tx queue %d for port %d\n", __FUNCTION__, queue, port);
            goto err;
        }
    }

    ret = rte_eth_dev_start(device->port);
    if (ret != 0)
    {
        DPE(dpdk_intf->errbuf, "%s: Couldn't start device for port %d\n", __FUNCTION__, port);
        goto err;
    }

    if (dpdk_intf->promisc_flag)
        rte_eth_promiscuous_enable(port);

    {
    	struct rte_eth_hash_filter_info info;
    	int ret;
    	if (rte_eth_dev_filter_supported(port, RTE_ETH_FILTER_HASH) == 0) {

			memset(&info, 0, sizeof(info));
			info.info_type = RTE_ETH_HASH_FILTER_SYM_HASH_ENA_PER_PORT;
			info.info.enable = 1;
			printf("Set syn hash filter on port %i\n", port);
			ret = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_HASH, RTE_ETH_FILTER_SET, &info);
			if (ret < 0) {
				printf("Cannot set symmetric hash enable per port on "
							"port %u\n", port);
			}
    	}
    }

    device->flags |= DPDKINST_STARTED;
    RELEASE_LOCK(&port_lock[port]);
    return DAQ_SUCCESS;

err:
  RELEASE_LOCK(&port_lock[port]);
  return DAQ_ERROR;
}

static void destroy_device(DpdkDevice **device)
{
	if (!device) return;
    if (*device)
    {
        if (--(*device)->ref_cnt == 0)
        {
            (*device)->flags &= ~DPDKINST_STARTED;
            rte_eth_dev_stop((*device)->port);
            rte_eth_dev_close((*device)->port);
            free(*device);
        	*device = NULL;
        }
    }
}

/* NOTE this function must be mutex protected */
static DpdkDevice *create_rx_device(const char *port_name, uint16_t *rx_queue, char *errbuf,
		size_t errlen, int queues, int debug)
{
    DpdkDevice *device;
    int i, port;
    char poolname[64];
    static int index = 0;
	struct rte_eth_dev_info inf;

	*rx_queue = 0;
	if (strncmp(port_name, "dpdk", 4) != 0 || sscanf(&port_name[4], "%d", &port) != 1)
	{
		snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!", __FUNCTION__, port_name);
		return NULL;
	}


    for (i = 0; i < num_dpdk_devices; i++)
    {
    	if (port == dpdk_devices[i]->port)
    	{
#ifndef USE_RX_TX_LOCKING
    		if (dpdk_devices[i]->num_rx_queues >= dpdk_devices[i]->max_rx_queues)
    			return NULL;
#endif
    		// dpdk device already created - add a queue
    		if (debug)
    	        printf("DPDK - device found with port = %i, number of queues %i\n",
    		    		port, dpdk_devices[i]->num_rx_queues + 1);

		    if (dpdk_devices[i]->flags & DPDKINST_STARTED)
		    {
		    	printf("INTERNAL ERROR - device created too late!\n");
		    	return NULL;
		    }
			*rx_queue =  MODULUS(dpdk_devices[i]->num_rx_queues,dpdk_devices[i]->max_rx_queues);

			dpdk_devices[i]->num_rx_queues++;
			dpdk_devices[i]->ref_cnt++;


			if (dpdk_devices[i]->mbuf_pool[*rx_queue] == NULL)
			{
				snprintf(poolname, sizeof(poolname), "MBUF_POOL%d:%d", port, *rx_queue);
				dpdk_devices[i]->mbuf_pool[*rx_queue] = rte_pktmbuf_pool_create(poolname,
						NUM_MBUFS / dpdk_devices[i]->max_rx_queues,
						MBUF_CACHE_SIZE, 0, MBUF_PKT_SIZE, rte_socket_id());
				if (dpdk_devices[i]->mbuf_pool[*rx_queue] == NULL)
				{
					snprintf(errbuf, errlen, "%s: Couldn't create mbuf pool!\n", __FUNCTION__);
					goto err;
				}
			}

			return dpdk_devices[i];
    	}
	}

    /* New DPDK port device needed */
    device = calloc(1, sizeof(DpdkDevice));
    if (!device)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate a new device structure.", __FUNCTION__);
        goto err;
    }
    /* This thread is the only one allowed to setup and start the device */
    device->tid = pthread_self();
    device->index = index++;
    device->port = port;
    device->ref_cnt = 1;

	rte_eth_dev_info_get(port, &inf);
	if (debug)
	{
		printf("driver name: %s\n", inf.driver_name);
		printf("max Rx pktlen: %i\n", inf.max_rx_pktlen);
		printf("Max Rx queues: %i\n", inf.max_rx_queues);
		printf("Max Tx queues: %i\n", inf.max_tx_queues);
		printf("Daq Port ID    %i\n", device->index);
	}

	if (queues >= 1)
	{
	    inf.max_rx_queues = RTE_MIN(inf.max_rx_queues, queues);
        inf.max_tx_queues = RTE_MIN(inf.max_tx_queues, queues);
	}

    device->max_rx_queues = RTE_MIN(MAX_RX_QUEUES, inf.max_rx_queues);
    device->max_tx_queues = RTE_MIN(MAX_TX_QUEUES, inf.max_tx_queues);
	device->num_rx_queues = 1;

    snprintf(poolname, sizeof(poolname), "MBUF_POOL%d:0", port);
    device->mbuf_pool[0] = rte_pktmbuf_pool_create(poolname, NUM_MBUFS / device->max_rx_queues,
                MBUF_CACHE_SIZE, 0, MBUF_PKT_SIZE, rte_socket_id());
    if (device->mbuf_pool[0] == NULL)
    {
        snprintf(errbuf, errlen, "%s: Couldn't create mbuf pool!\n", __FUNCTION__);
        goto err;
    }

    if (num_dpdk_devices < MAX_DPDK_DEVICES)
    	dpdk_devices[num_dpdk_devices++] = device;
    else
    	goto err;

    if (debug)
      printf("DPDK - device created on port = %i\n", port);

 	*rx_queue = 0; // always first queue
    return device;

err:
    destroy_device(&device);
    return NULL;
}


static int create_bridge(Dpdk_Interface_t *dpdk_intf)
{
	int i;

	/* Add Tx functionality for inline on both devices */
	for (i = 0; i < LINK_NUM_DEVS; i++)
	{
#ifndef USE_RX_TX_LOCKING
		if (dpdk_intf->link[i].dev->num_tx_queues >= dpdk_intf->link[i].dev->max_tx_queues)
			return DAQ_ERROR_NODEV;
#endif
		dpdk_intf->link[i].tx_queue = MODULUS(dpdk_intf->link[i].dev->num_tx_queues, dpdk_intf->link[i].dev->max_tx_queues);
		dpdk_intf->link[i].dev->num_tx_queues++;
	}
	if (dpdk_intf->debug)
	{
		printf("Created bridge between port %i and port %i, dev rx queue %i, dev tx queue %i, peer rx queue %i, peer tx queue %i\n",
				dpdk_intf->link[DEV_IDX].dev->port, dpdk_intf->link[PEER_IDX].dev->port, dpdk_intf->link[DEV_IDX].rx_queue,
				dpdk_intf->link[DEV_IDX].tx_queue, dpdk_intf->link[PEER_IDX].rx_queue, dpdk_intf->link[PEER_IDX].tx_queue);
	}

    return DAQ_SUCCESS;
}



static int dpdk_close(Dpdk_Interface_t *dpdk_intf)
{
	int i;
    if (!dpdk_intf)
    {
        return -1;
    }

	for (i = 0; i < LINK_NUM_DEVS; i++)
	{
		if (dpdk_intf->link[i].dev)
		{
			destroy_device(&dpdk_intf->link[i].dev);
		}
	}

    sfbpf_freecode(&dpdk_intf->fcode);
    dpdk_intf->state = DAQ_STATE_STOPPED;

    return 0;
}

static int parse_args(char *inputstring, char **argv)
{
    char **ap;

    for (ap = argv; (*ap = strsep(&inputstring, " \t")) != NULL;)
    {
        if (**ap != '\0')
            if (++ap >= &argv[MAX_ARGS])
                break;
    }
    return ap - argv;
}


static int dpdk_daq_initialize(const DAQ_Config_t *config, void **ctxt_ptr, char *errbuf, size_t errlen)
{
    Dpdk_Interface_t *dpdk_intf;
    DpdkDevice *device;
    DAQ_Dict *entry;
    char dpdk_port[IFNAMSIZ];
    int num_ports = 0;
    size_t len;
    int ret, rval = DAQ_ERROR;
    char *dpdk_args = NULL;
    char argv0[] = "fake";
    char *argv[MAX_ARGS + 1];
    int argc;
    uint16_t queue;
    char *dev = NULL;
    static char interface_name[1024] = "";
    static uint16_t dev_idx = 0;
    static int debug = 0;
	static int first = 1, ports = 0, dpdk_queues = 1;
	static volatile uint32_t threads_in = 0;

	threads_in++;
	TAKE_LOCK(&port_lock[MAX_PORTS]);

    dpdk_intf = calloc(1, sizeof(Dpdk_Interface_t));
    if (!dpdk_intf)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the new DPDK context!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    /* Make sure only 1 Interface string is specified */
    if (interface_name[0] == 0) {
        if (strlen(config->name) > sizeof(interface_name)-1) {
            snprintf(errbuf, errlen, "%s: Invalid interface - too long!", __FUNCTION__);
            goto err;
        }
        strcpy(interface_name, config->name);
    }
    else
    {
        if (strcmp(interface_name, config->name) != 0) {
            snprintf(errbuf, errlen, "%s: Only 1 -i command supported on this DAQ!", __FUNCTION__);
            goto err;
        }
    }

    dpdk_intf->descr = strdup(config->name);
    if (!dpdk_intf->descr)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    dpdk_intf->snaplen = config->snaplen;
    dpdk_intf->timeout = (config->timeout > 0) ? (int) config->timeout : -1;
    dpdk_intf->promisc_flag = (config->flags & DAQ_CFG_PROMISC);


    if (first) {
		/* Import the DPDK arguments and other configuration values. */
		for (entry = config->values; entry; entry = entry->next)
		{
			if (!strcmp(entry->key, "dpdk_args"))
				dpdk_args = entry->value;
			else
			{
				if (!strcmp(entry->key, "debug"))
					debug = 1;
				else
				{
					if (!strcmp(entry->key, "dpdk_queues"))
					{
						dpdk_queues = atoi(entry->value);
						if (dpdk_queues < 1) dpdk_queues = 1;
					}
				}
			}
		}

		argv[0] = argv0;
		argc = parse_args(dpdk_args, &argv[1]) + 1;
		optind = 1;

		ret = rte_eal_init(argc, argv);
		if (ret < 0)
		{
			snprintf(errbuf, errlen, "%s: Invalid EAL arguments!\n", __FUNCTION__);
			rval = DAQ_ERROR_INVAL;
			goto err;
		}
	    ports = rte_eth_dev_count();
	    if (ports == 0)
	    {
	        snprintf(errbuf, errlen, "%s: No Ethernet ports!\n", __FUNCTION__);
	        rval = DAQ_ERROR_NODEV;
	        goto err;
	    }
		first = 0;
    }

    dev = dpdk_intf->descr;

    dpdk_intf->debug = debug;


    while (dev[dev_idx] != '\0')
    {
        len = strcspn(&dev[dev_idx], ": ");
        if (len >= sizeof(dpdk_port))
        {
            snprintf(errbuf, errlen, "%s: Interface name too long! (%zu)", __FUNCTION__, len);
            goto err;
        }
        if (len != 0)
        {
            snprintf(dpdk_port, len + 1, "%s", &dev[dev_idx]);

            num_ports++;
            device = create_rx_device(dpdk_port, &queue, errbuf, errlen, dpdk_queues, dpdk_intf->debug);
            if (!device)
                goto err;

            dev_idx += len + 1;

            if (config->mode != DAQ_MODE_PASSIVE)
            {
                if (num_ports == 2)
                {
					dpdk_intf->link[PEER_IDX].dev = device;
					dpdk_intf->link[PEER_IDX].rx_queue = queue;

                    if (create_bridge(dpdk_intf) != DAQ_SUCCESS)
                    {
                        snprintf(errbuf, errlen, "%s: Couldn't create the bridge between dpdk%d and dpdk%d!",
                                 __FUNCTION__, dpdk_intf->link[DEV_IDX].dev->port, dpdk_intf->link[PEER_IDX].dev->port);
                        goto err;
                    }
                    break;
                }
                else
                {
                    if (dev[dev_idx-1] != ':')
                    {
                        snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s' - inline, but not \":\" separated!",
                                __FUNCTION__, dpdk_intf->descr);
                        goto err;
                    }
					dpdk_intf->link[DEV_IDX].dev = device;
					dpdk_intf->link[DEV_IDX].rx_queue = queue;
                }
            }
            else
            {
                if (dev[dev_idx-1] == ':')
                {
                    snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s' - passive, but \":\" separator found!",
                            __FUNCTION__, dpdk_intf->descr);
                    goto err;
                }
            	dpdk_intf->link[DEV_IDX].dev = device;
            	dpdk_intf->link[DEV_IDX].rx_queue = queue;
            	if (dpdk_intf->link[DEV_IDX].dev->max_tx_queues)
            	{
            		dpdk_intf->link[DEV_IDX].dev->num_tx_queues = 1;
            		dpdk_intf->link[DEV_IDX].tx_queue = 0;
            	}
            	break;
            }
        }
        else
          break;
    }

    if (strlen(dev) <= dev_idx) dev_idx = 0;

    /* If there are any leftover unbridged interfaces and we're not in Passive mode, error out. */
    if (!dpdk_intf->link[DEV_IDX].dev || (config->mode != DAQ_MODE_PASSIVE && !dpdk_intf->link[PEER_IDX].dev))
    {
        snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!",
                __FUNCTION__, dpdk_intf->descr);
        goto err;
    }

    dpdk_intf->state = DAQ_STATE_INITIALIZED;

#ifdef DEBUG_SHOW_LOCAL_STATISTICS
    /* Link up globally for local stats */
    dpdk_intf->next = base_intf;
    base_intf = dpdk_intf;
#endif

    *ctxt_ptr = dpdk_intf;

    RELEASE_LOCK(&port_lock[MAX_PORTS]);
    threads_in--;

    do
    {
        /* Wait for other threads to finish */
        sleep(1);
    } while (threads_in);

    return DAQ_SUCCESS;

err:
    if (dpdk_intf)
    {
        dpdk_close(dpdk_intf);
        if (dpdk_intf->descr)
            free(dpdk_intf->descr);
        free(dpdk_intf);
    }

    RELEASE_LOCK(&port_lock[MAX_PORTS]);
    threads_in--;
    return rval;
}

static int dpdk_daq_set_filter(void *handle, const char *filter)
{
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;
    struct sfbpf_program fcode;

    if (dpdk_intf->filter)
        free(dpdk_intf->filter);

    dpdk_intf->filter = strdup(filter);
    if (!dpdk_intf->filter)
    {
        DPE(dpdk_intf->errbuf, "%s: Couldn't allocate memory for the filter string!", __FUNCTION__);
        return DAQ_ERROR;
    }

    if (sfbpf_compile(dpdk_intf->snaplen, DLT_EN10MB, &fcode, dpdk_intf->filter, 1, 0) < 0)
    {
        DPE(dpdk_intf->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
        return DAQ_ERROR;
    }

    sfbpf_freecode(&dpdk_intf->fcode);
    dpdk_intf->fcode.bf_len = fcode.bf_len;
    dpdk_intf->fcode.bf_insns = fcode.bf_insns;

    return DAQ_SUCCESS;
}

static int dpdk_daq_start(void *handle)
{
	int i;
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;
	for (i = 0; i < LINK_NUM_DEVS; i++)
	{
		if (dpdk_intf->link[i].dev)
		{
			if (start_device(dpdk_intf, dpdk_intf->link[i].dev) != DAQ_SUCCESS)
				return DAQ_ERROR;
		}
	}
    dpdk_daq_reset_stats(handle);
    dpdk_intf->state = DAQ_STATE_STARTED;
    return DAQ_SUCCESS;
}

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_IGNORE */
    DAQ_VERDICT_BLOCK       /* DAQ_VERDICT_RETRY */
};


static int dpdk_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user)
{
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;
    DpdkLink *link = (DpdkLink *)&dpdk_intf->link;
    DpdkDevice *device, *peer;
    DAQ_PktHdr_t daqhdr;
    DAQ_Verdict verdict;
    const uint8_t *data;
    uint16_t len, dev_queue = 0, peer_queue = 0;
    int c = 0, burst_size;
    int i, got_one, ignored_one, sent_one;
    int alt;
    struct timeval ts;
    struct rte_mbuf *tx_burst[BURST_SIZE];
    uint32_t tx_num;

#ifdef DEBUG_SHOW_LOCAL_STATISTICS
    if (dpdk_intf->debug) {
		TAKE_LOCK(&port_lock[MAX_PORTS]);
		int n,nn;
		for (n=0; n<num_dpdk_devices; n++)
		{
			printf("Rx[port %i]: ", dpdk_devices[n]->port);
			for (nn=0; nn < RTE_MIN(dpdk_devices[n]->num_rx_queues, dpdk_devices[n]->max_rx_queues); nn++)
			{
				printf("q[%i](%lu), ",nn, dpdk_devices[n]->rx_pkts[nn]);
			}
			printf("\nTx[port %i]: ", dpdk_devices[n]->port);
			for (nn=0; nn < RTE_MIN(dpdk_devices[n]->num_tx_queues, dpdk_devices[n]->max_tx_queues); nn++)
			{
				printf("q[%i](%lu), ",nn, dpdk_devices[n]->tx_pkts[nn]);
			}
			printf("\n");
		}
		{
			Dpdk_Interface_t *intf = base_intf;
			int num = 0;
			while (intf)
			{
			    if (intf->link[1].dev) {
                    printf("Thread[%i] port %i:%i Rx(%lu) -> port %i:%i Tx(%lu)\n", num,
                            intf->link[0].dev->port, intf->link[0].rx_queue, intf->link[0].rx_pkts,
                            intf->link[1].dev->port, intf->link[1].tx_queue, intf->link[1].tx_pkts);

                    printf("Thread[%i] port %i:%i Rx(%lu) -> port %i:%i Tx(%lu)\n", num,
                            intf->link[1].dev->port, intf->link[1].rx_queue, intf->link[1].rx_pkts,
                            intf->link[0].dev->port, intf->link[0].tx_queue, intf->link[0].tx_pkts);
			    }
			    else
			    {
                    printf("Thread[%i] port %i:%i Rx(%lu)\n", num,
                            intf->link[0].dev->port, intf->link[0].rx_queue, intf->link[0].rx_pkts);
			    }
				num++;
				intf = intf->next;
			}
		}
		printf("\n");
		RELEASE_LOCK(&port_lock[MAX_PORTS]);
    }
#endif

    while (c < cnt || cnt <= 0)
    {
        struct rte_mbuf *bufs[BURST_SIZE];

        got_one = 0;
        ignored_one = 0;
        sent_one = 0;

        for (alt = 0; alt < LINK_NUM_DEVS; alt++)
        {
        	if (link[alt].dev == NULL) continue;
        	device = link[alt].dev;
        	dev_queue = link[alt].rx_queue;
        	peer = link[alt^1].dev;
        	peer_queue = link[alt^1].tx_queue;
            tx_num = 0;
            /* Has breakloop() been called? */
            if (dpdk_intf->break_loop)
            {
                dpdk_intf->break_loop = 0;
                return 0;
            }

            {
                gettimeofday(&ts, NULL);

                if (cnt <= 0 || cnt - c >= BURST_SIZE)
                    burst_size = BURST_SIZE;
                else
                    burst_size = cnt - c;

#ifdef USE_RX_TX_LOCKING
                pthread_mutex_lock(&rx_mutex[device->port][dev_queue]);
#endif
                const uint16_t nb_rx =
                    rte_eth_rx_burst(device->port, dev_queue,
                            bufs, burst_size);

#ifdef USE_RX_TX_LOCKING
                pthread_mutex_unlock(&rx_mutex[device->port][dev_queue]);
#endif

                if (unlikely(nb_rx == 0))
                    continue;

#ifdef DEBUG_SHOW_LOCAL_STATISTICS
                if (dpdk_intf->debug)
                {
                    device->rx_pkts[dev_queue] += nb_rx;
                    link[alt].rx_pkts += nb_rx;
                }
#endif

#ifdef BATCH_AWARE
                 {
                	struct rte_mbuf pkt;
                	struct rte_mbuf_batch_ctrl ctrl;

					for (i = 0; i < nb_rx; i++)
					{
						verdict = DAQ_VERDICT_PASS;
						bufs[i]->ol_flags |= PKT_BATCH;
						rte_pktmbuf_adj(bufs[i], sizeof(struct rte_mbuf_batch_pkt_hdr));
						bufs[i]->batch_size = bufs[i]->pkt_len;

	            		if (!rte_pktmbuf_batch_get_first(bufs[i], &pkt, &ctrl)) continue;
	            		do {
							data = rte_pktmbuf_mtod(&pkt, void *);
							len = pkt.data_len;

							dpdk_intf->stats.hw_packets_received++;

							if (dpdk_intf->fcode.bf_insns && sfbpf_filter(dpdk_intf->fcode.bf_insns, data, len, len) == 0)
							{
								ignored_one = 1;
								dpdk_intf->stats.packets_filtered++;
								continue;
							}
							got_one = 1;

							daqhdr.ts = ts;
							daqhdr.caplen = len;
							daqhdr.pktlen = len;
							daqhdr.ingress_index = device->index;
							daqhdr.egress_index = peer ? peer->index : DAQ_PKTHDR_UNKNOWN;
							daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
							daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
							daqhdr.flags = 0;
							daqhdr.opaque = 0;
							daqhdr.priv_ptr = NULL;
							daqhdr.address_space_id = 0;

							if (callback)
							{
								verdict = callback(user, &daqhdr, data);
								if (verdict >= MAX_DAQ_VERDICT)
									verdict = DAQ_VERDICT_PASS;
								dpdk_intf->stats.verdicts[verdict]++;
								verdict = verdict_translation_table[verdict];
							}
							dpdk_intf->stats.packets_received++;
							c++;

					    } while (rte_pktmbuf_batch_get_next(bufs[i], &pkt, &ctrl));

						if (peer)
						{
							bufs[i]->pkt_len = bufs[i]->batch_size;
							bufs[i]->data_len = bufs[i]->pkt_len;
							rte_pktmbuf_prepend(bufs[i], sizeof(struct rte_mbuf_batch_pkt_hdr));

							tx_burst[tx_num] = bufs[i];
							tx_num++;
						}
						else
						{
							rte_pktmbuf_free(bufs[i]);
						}
					}
                }
#else
                {
                    for (i = 0; i < nb_rx; i++)
                    {
                        verdict = DAQ_VERDICT_PASS;

                        data = rte_pktmbuf_mtod(bufs[i], void *);
                        len = rte_pktmbuf_data_len(bufs[i]);

                        dpdk_intf->stats.hw_packets_received++;

                        if (dpdk_intf->fcode.bf_insns && sfbpf_filter(dpdk_intf->fcode.bf_insns, data, len, len) == 0)
                        {
                            ignored_one = 1;
                            dpdk_intf->stats.packets_filtered++;
                            goto send_packet;
                        }
                        got_one = 1;

                        daqhdr.ts = ts;
                        daqhdr.caplen = len;
                        daqhdr.pktlen = len;
                        daqhdr.ingress_index = device->index;
                        daqhdr.egress_index = peer ? peer->index : DAQ_PKTHDR_UNKNOWN;
                        daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
                        daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
                        daqhdr.flags = 0;
                        daqhdr.opaque = 0;
                        daqhdr.priv_ptr = NULL;
                        daqhdr.address_space_id = 0;

                        if (callback)
                        {
                            verdict = callback(user, &daqhdr, data);
                            if (verdict >= MAX_DAQ_VERDICT)
                                verdict = DAQ_VERDICT_PASS;
                            dpdk_intf->stats.verdicts[verdict]++;
                            verdict = verdict_translation_table[verdict];
                        }
                        dpdk_intf->stats.packets_received++;
                        c++;
send_packet:

                        if (verdict == DAQ_VERDICT_PASS && peer)
                        {
                            tx_burst[tx_num] = bufs[i];
                            tx_num++;
                        }
                        else
                        {
                            rte_pktmbuf_free(bufs[i]);
                        }
                    }

                }
#endif
            }

            if (peer)
            {
    			uint32_t nbidx = 0,i,cnt=0;
                if (unlikely(tx_num == 0))
                    continue;

#ifdef USE_RX_TX_LOCKING
                pthread_mutex_lock(&tx_mutex[peer->port][peer_queue]);
#endif
				do
				{
                    uint16_t nb_tx;
                    nb_tx = rte_eth_tx_burst(peer->port, peer_queue, &tx_burst[nbidx], tx_num - nbidx);
                    nbidx += nb_tx;
				} while (nbidx < tx_num && ++cnt < 100);

#ifdef USE_RX_TX_LOCKING
                pthread_mutex_unlock(&tx_mutex[peer->port][peer_queue]);
#endif

#ifdef DEBUG_SHOW_LOCAL_STATISTICS
                if (dpdk_intf->debug)
                {
                    peer->tx_pkts[peer_queue] += nbidx;
                    link[alt^1].tx_pkts += nbidx;
                }
#endif
                if (unlikely(nbidx < tx_num))
                {
                    for (i = nbidx; i < tx_num; i++)
                    {
                        rte_pktmbuf_free(tx_burst[i]);
                    }
                }
				sent_one = 1;
            }
        }

        if ((!got_one && !ignored_one && !sent_one))
        {
            struct timeval now;

            if (dpdk_intf->timeout == -1)
                continue;

            /* If time out, return control to the caller. */
            gettimeofday(&now, NULL);
            if (now.tv_sec > ts.tv_sec ||
                    (now.tv_usec - ts.tv_usec) > dpdk_intf->timeout * 1000)
                return 0;
        }
        else
        {
            gettimeofday(&ts, NULL);
        }
    }

    return 0;
}

static int dpdk_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse)
{
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;
    int tx_index;
    uint16_t tx_queue, rx_queue;
    DpdkDevice *device = NULL;
    struct rte_mbuf *m;

    if (reverse)
    {
        if (!dpdk_intf->link[DEV_IDX].dev ||
            !dpdk_intf->link[DEV_IDX].dev->max_tx_queues)
            return DAQ_ERROR_NODEV;

        tx_index = hdr->ingress_index;
        tx_queue = dpdk_intf->link[DEV_IDX].tx_queue;
        rx_queue = dpdk_intf->link[PEER_IDX].rx_queue;

        device = dpdk_intf->link[DEV_IDX].dev;
    }
    else
    {
        if (!dpdk_intf->link[PEER_IDX].dev ||
            !dpdk_intf->link[PEER_IDX].dev->max_tx_queues)
            return DAQ_ERROR_NODEV;

        tx_index = hdr->egress_index;
        tx_queue = dpdk_intf->link[PEER_IDX].tx_queue;
        rx_queue = dpdk_intf->link[DEV_IDX].rx_queue;

        device = dpdk_intf->link[PEER_IDX].dev;
    }

    if (!device || device->index != tx_index)
    {
        DPE(dpdk_intf->errbuf, "%s: Unrecognized interface specified: %u",
                __FUNCTION__, tx_index);
        return DAQ_ERROR_NODEV;
    }

    m = rte_pktmbuf_alloc(device->mbuf_pool[rx_queue]);
    if (!m)
    {
        DPE(dpdk_intf->errbuf, "%s: Couldn't allocate memory for packet.",
                __FUNCTION__);
        return DAQ_ERROR_NOMEM;
    }

    rte_memcpy(rte_pktmbuf_mtod(m, void *), packet_data, len);
    rte_pktmbuf_data_len(m) = len;

#ifdef USE_RX_TX_LOCKING
    pthread_mutex_lock(&tx_mutex[device->port][tx_queue]);
#endif

    const uint16_t nb_tx = rte_eth_tx_burst(device->port, tx_queue, &m, 1);

#ifdef USE_RX_TX_LOCKING
    pthread_mutex_unlock(&tx_mutex[device->port][tx_queue]);
#endif

    if (unlikely(nb_tx == 0))
    {
        DPE(dpdk_intf->errbuf, "%s: Couldn't send packet. Try again.", __FUNCTION__);
        rte_pktmbuf_free(m);
        return DAQ_ERROR_AGAIN;
    }

    return DAQ_SUCCESS;
}

static int dpdk_daq_breakloop(void *handle)
{
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;

    dpdk_intf->break_loop = 1;

    return DAQ_SUCCESS;

}

static int dpdk_daq_stop(void *handle)
{
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;

    TAKE_LOCK(&port_lock[MAX_PORTS]);
    dpdk_close(dpdk_intf);
    RELEASE_LOCK(&port_lock[MAX_PORTS]);

    return DAQ_SUCCESS;
}

static void dpdk_daq_shutdown(void *handle)
{
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;

    TAKE_LOCK(&port_lock[MAX_PORTS]);
    dpdk_close(dpdk_intf);
    if (dpdk_intf->descr)
        free(dpdk_intf->descr);
    if (dpdk_intf->filter)
        free(dpdk_intf->filter);
    free(dpdk_intf);
    RELEASE_LOCK(&port_lock[MAX_PORTS]);
}

static DAQ_State dpdk_daq_check_status(void *handle)
{
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;

    return dpdk_intf->state;
}

static int dpdk_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;

    rte_memcpy(stats, &dpdk_intf->stats, sizeof(DAQ_Stats_t));

    return DAQ_SUCCESS;
}

static void dpdk_daq_reset_stats(void *handle)
{
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;

    memset(&dpdk_intf->stats, 0, sizeof(DAQ_Stats_t));
}

static int dpdk_daq_get_snaplen(void *handle)
{
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;

    return dpdk_intf->snaplen;
}

static uint32_t dpdk_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |
        DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_BPF |
        DAQ_CAPA_DEVICE_INDEX;
}

static int dpdk_daq_get_datalink_type(void *handle)
{
    return DLT_EN10MB;
}

static const char *dpdk_daq_get_errbuf(void *handle)
{
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;

    return dpdk_intf->errbuf;
}

static void dpdk_daq_set_errbuf(void *handle, const char *string)
{
    Dpdk_Interface_t *dpdk_intf = (Dpdk_Interface_t *) handle;

    if (!string)
        return;

    DPE(dpdk_intf->errbuf, "%s", string);
}

static int dpdk_daq_get_device_index(void *handle, const char *name)
{
    int port, i;

    if (strncmp(name, "dpdk", 4) != 0 || sscanf(&name[4], "%d", &port) != 1)
        return DAQ_ERROR_NODEV;

    for (i = 0; i < num_dpdk_devices; i++)
    {
        if (dpdk_devices[i]->port == port)
            return dpdk_devices[i]->index;
    }

    return DAQ_ERROR_NODEV;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
const DAQ_Module_t dpdk_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_API_VERSION,
    /* .module_version = */ DAQ_DPDK_VERSION,
    /* .name = */ "dpdk",
    /* .type = */ DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .initialize = */ dpdk_daq_initialize,
    /* .set_filter = */ dpdk_daq_set_filter,
    /* .start = */ dpdk_daq_start,
    /* .acquire = */ dpdk_daq_acquire,
    /* .inject = */ dpdk_daq_inject,
    /* .breakloop = */ dpdk_daq_breakloop,
    /* .stop = */ dpdk_daq_stop,
    /* .shutdown = */ dpdk_daq_shutdown,
    /* .check_status = */ dpdk_daq_check_status,
    /* .get_stats = */ dpdk_daq_get_stats,
    /* .reset_stats = */ dpdk_daq_reset_stats,
    /* .get_snaplen = */ dpdk_daq_get_snaplen,
    /* .get_capabilities = */ dpdk_daq_get_capabilities,
    /* .get_datalink_type = */ dpdk_daq_get_datalink_type,
    /* .get_errbuf = */ dpdk_daq_get_errbuf,
    /* .set_errbuf = */ dpdk_daq_set_errbuf,
    /* .get_device_index = */ dpdk_daq_get_device_index,
    /* .modify_flow = */ NULL,
    /* .hup_prep = */ NULL,
    /* .hup_apply = */ NULL,
    /* .hup_post = */ NULL,
    /* .dp_add_dc = */ NULL,
	/* .query_flow = */ NULL
};
