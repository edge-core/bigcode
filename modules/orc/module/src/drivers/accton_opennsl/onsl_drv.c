/************************************************************
 * <bsn.cl fy=2013 v=epl>
 * 
 *        Copyright 2015 Accton Corporation
 * 
 * Licensed under the Eclipse Public License, Version 1.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * 
 *        http://www.eclipse.org/legal/epl-v10.html
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the
 * License.
 * 
 * </bsn.cl>
 ************************************************************
 *
 * ORC driver for Accton OpenNSL
 *
 ***********************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#include <sal/types.h>
#include <sal/driver.h>

#include <opennsl/error.h>
#include <opennsl/init.h>
#include <opennsl/l3.h>
#include <opennsl/port.h>
#include <opennsl/stack.h>
#include <opennsl/types.h>
#include <opennsl/tx.h>

#define DEBUG_THRESHOLD *onsl_drv_debug_threshold
#include <orc/utils.h>
#include <orc/orc_logger.h>
#include <orc/orc_driver.h>

#define ONSL_DRV_TX_COS         7
#define ONSL_DRV_USER_PORT_INDEX_INVALID    0xffff

typedef struct onsl_drv_port {
    port_t user_port;
    int drv_unit;
    opennsl_port_t drv_port;
} onsl_drv_port_t;

static orc_options_t *orc_options;
static onsl_drv_port_t *onsl_drv_ports;
static int onsl_drv_ports_num = -1;
static int onsl_drv_max_unit = -1;
#if 0 /* l3_host */
static int onsl_drv_cpu_l3_intf = -1;
#endif /* l3_host */
static enum Debug_Thresholds _DEBUG_THRESHOLD = ORC_LOG_INFO;
enum Debug_Thresholds *onsl_drv_debug_threshold = &_DEBUG_THRESHOLD;


/***************
 * init: just print args
 */

static int
onsl_drv_init_driver(orc_options_t * options, int argc, char * argv[])
{
    int drv_unit;
    opennsl_port_t drv_port;
    int rv;
    int i;

    {
        orc_debug("Init driver\n");
    }

    orc_options = options;

    if (onsl_drv_max_unit != -1)
    {
        return 0;
    }

    /* TODO: orc doesn't pass correct argc/argv.
     */
    {
        int i;

        for (i = 0; i < argc; i++)
        {
            orc_debug("arg %d = %s\n", i, argv[i]);

            if (strcmp(argv[i], "--accton-debug") == 0)
            {
                onsl_drv_debug_threshold = &options->debug;
                orc_log("Setting Debug level to %d\n", *onsl_drv_debug_threshold);
            }
        }
    }

    OPENNSL_IF_ERROR_RETURN(opennsl_driver_init());

    if (onsl_drv_max_unit == -1)
    {
        OPENNSL_IF_ERROR_RETURN(opennsl_attach_max(&onsl_drv_max_unit));
    }

#if 0 /* l3_host */
    if (onsl_drv_max_unit >= 0)
    {
        opennsl_l3_intf_t intf;

        opennsl_l3_intf_t_init(&intf);

        sal_memset(intf.l3a_mac_addr, 0xff, sizeof(opennsl_mac_t));
        intf.l3a_vid = 0;

        if (OPENNSL_SUCCESS(opennsl_l3_intf_find(0, &intf)))
        {
            onsl_drv_cpu_l3_intf = intf.l3a_intf_id;
        }
    }
#endif /* l3_host */

    /* TODO: orc doesn't handle pkt well now.
     */
    for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
    {
        #define opennslSwitchIcmpRedirectToCpu 75
        #define opennslSwitchL3MtuFailToCpu 129
        #define opennslSwitchL3UcTtlErrToCpu 47
        #define opennslSwitchL3SlowpathToCpu 48
        #define opennslSwitchV4L3DstMissToCpu 43
        #define opennslSwitchV4L3ErrToCpu 42
        #define opennslSwitchV6L3DstMissToCpu 40
        #define opennslSwitchNdPktToCpu 89
        #define opennslSwitchL3EgressMode 230

        rv = opennsl_switch_control_set(drv_unit, opennslSwitchArpReplyToCpu, 1);
        rv = opennsl_switch_control_set(drv_unit, opennslSwitchArpRequestToCpu, 1);
        rv = opennsl_switch_control_set(drv_unit, opennslSwitchIcmpRedirectToCpu, 1);
        rv = opennsl_switch_control_set(drv_unit, opennslSwitchDhcpPktToCpu, 1);
        rv = opennsl_switch_control_set(drv_unit, opennslSwitchL3MtuFailToCpu, 1);
        rv = opennsl_switch_control_set(drv_unit, opennslSwitchL3UcTtlErrToCpu, 1);
        rv = opennsl_switch_control_set(drv_unit, opennslSwitchL3SlowpathToCpu, 1);
        rv = opennsl_switch_control_set(drv_unit, opennslSwitchL3UcastTtl1ToCpu, 1);
        rv = opennsl_switch_control_set(drv_unit, opennslSwitchV4L3DstMissToCpu, 1);
        rv = opennsl_switch_control_set(drv_unit, opennslSwitchV4L3ErrToCpu, 1);
        //rv = opennsl_switch_control_set(drv_unit, opennslSwitchV6L3DstMissToCpu, 1);
        //rv = opennsl_switch_control_set(drv_unit, opennslSwitchNdPktToCpu, 1);
        //rv = opennsl_switch_control_set(drv_unit, opennslSwitchL3EgressMode, 1);
    }

    if (onsl_drv_ports_num == -1)
    {
        onsl_drv_port_t * dport;
        int drv_unit;
        int total_count;
        int user_port_idx;

#if ONSL_DRV_USE_ACCTON_USER_PORT_PROBE
        extern int accton_user_port_probe(int *user_port, int *drv_unit, int *drv_port);

        total_count = accton_user_port_probe(NULL, NULL, NULL);
#else /* ONSL_DRV_USE_ACCTON_USER_PORT_PROBE */
        /* calculate total_count
         */
        total_count = 0;

        for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
        {
            opennsl_port_config_t pconfig;
            int count;
            opennsl_port_config_t_init(&pconfig);
            OPENNSL_IF_ERROR_RETURN(opennsl_port_config_get(drv_unit, &pconfig));
            OPENNSL_PBMP_COUNT(pconfig.e, count);
            total_count += count;
        }
#endif /* ONSL_DRV_USE_ACCTON_USER_PORT_PROBE */

        /* allocate buffer for onsl_drv_ports
         */
        if (total_count > 0 && onsl_drv_ports == NULL)
        {
            if (NULL == (onsl_drv_ports = calloc(total_count, sizeof(*onsl_drv_ports))))
            {
                orc_err("Out of mem allocating ports\n");
                return OPENNSL_E_MEMORY;
            }
        }

        /* fill in port info
         */
        i = 0;
#if ONSL_DRV_USE_ACCTON_USER_PORT_PROBE
        if (total_count > 0)
        {
            user_port_idx = 0;

            while (0 < accton_user_port_probe(&user_port_idx, &drv_unit, &drv_port))
            {
                if (i >= total_count)
                {
                    /* Exception: never happen */
                    break;
                }

                dport = &onsl_drv_ports[i++];

                dport->user_port.index = user_port_idx;
                dport->user_port.l3_intf_id = -1; /* just init for debug */
                dport->drv_unit = drv_unit;
                dport->drv_port = drv_port;
            }
        }
#else /* ONSL_DRV_USE_ACCTON_USER_PORT_PROBE */
        user_port_idx = 1;

        if (total_count > 0)
        {
            for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
            {
                opennsl_port_config_t pconfig;
                opennsl_port_config_t_init(&pconfig);
                OPENNSL_IF_ERROR_RETURN(opennsl_port_config_get(drv_unit, &pconfig));

                OPENNSL_PBMP_ITER(pconfig.e, drv_port)
                {
                    int enable;

                    if (i >= total_count)
                    {
                        /* Exception: never happen */
                        break;
                    }

                    /* skip disabled ports, just assign invalid user port to it.
                     */
                    enable = 0;
                    rv = opennsl_port_enable_set(drv_unit, drv_port, 1);
                    rv = opennsl_port_enable_get(drv_unit, drv_port, &enable);

                    dport = &onsl_drv_ports[i++];

                    dport->user_port.index = enable ? user_port_idx++ : ONSL_DRV_USER_PORT_INDEX_INVALID;
                    dport->user_port.l3_intf_id = -1; /* just init for debug */
                    dport->drv_unit = drv_unit;
                    dport->drv_port = drv_port;
                }
            }
        }
#endif /* ONSL_DRV_USE_ACCTON_USER_PORT_PROBE */

        onsl_drv_ports_num = i;
    }

    COMPILER_REFERENCE(rv);

    return 0;
}

/******************
 * discover_ports: generate some fake ports
 */

static int
onsl_drv_discover_ports(port_t * ports[], int * num)
{
    int i, j;

    {
        orc_debug("Discover ports: %d\n", onsl_drv_ports_num);
    }

    for (i = 0, j = 0; i < onsl_drv_ports_num; i++)
    {
        if (ports)
        {
            if (onsl_drv_ports[i].user_port.index == ONSL_DRV_USER_PORT_INDEX_INVALID)
            {
                continue;
            }

            if (j < *num)
            {
                ports[j++] = (port_t *) &onsl_drv_ports[i];
            }
        }
    }

    if (j > *num)
    {
        orc_err(" need to pre-allocate more ports: want %d got %d\n",
            onsl_drv_ports_num, *num);
        return OPENNSL_E_PARAM;
    }

    *num = j;
    return 0;
}

/*********
 * tx: just print to STDOUT
 */

static int
onsl_drv_tx_pkt(port_t *port, u8 *pkt, unsigned int len)
{
    onsl_drv_port_t *dport = (onsl_drv_port_t *)port;
    opennsl_pkt_t *drv_pkt = NULL;
    struct ether_header * eth = (struct ether_header *) pkt;
    int rv;

    {
        orc_debug("Sending packet from port %s to ASIC: "
                        ETH_FORMAT " -> " ETH_FORMAT " :: (0x%.4x) %u bytes\n",
                        port->name,
                        ETH_ADDR_PRINT(eth->ether_shost),
                        ETH_ADDR_PRINT(eth->ether_dhost),
                        ntohs(eth->ether_type),
                        len);
    }

    OPENNSL_IF_ERROR_RETURN(opennsl_pkt_alloc(dport->drv_unit, len, OPENNSL_TX_CRC_APPEND, &drv_pkt));

    memcpy(drv_pkt->pkt_data[0].data, pkt, len);
    drv_pkt->dest_port = dport->drv_port;
    drv_pkt->cos = ONSL_DRV_TX_COS;

    OPENNSL_PBMP_PORT_SET(drv_pkt->tx_pbmp, dport->drv_port);
    OPENNSL_PBMP_CLEAR(drv_pkt->tx_upbmp);

    if (ntohs(eth->ether_type) != 0x8100) {
        drv_pkt->flags |= OPENNSL_PKT_F_NO_VTAG;
    }

    /* TODO: or force untag for all pkt?
     */
    if (drv_pkt->flags & OPENNSL_PKT_F_NO_VTAG) {
        OPENNSL_PBMP_PORT_SET(drv_pkt->tx_upbmp, dport->drv_port);
    }

    opennsl_tx_pkt_setup(dport->drv_unit, drv_pkt);

    rv = opennsl_tx(dport->drv_unit, drv_pkt, NULL);

    if (drv_pkt) {
        opennsl_pkt_free(dport->drv_unit, drv_pkt);
    }

    OPENNSL_IF_ERROR_RETURN(rv);

    return 0;
}

static opennsl_rx_t onsl_drv_rx_cb(
    int unit, 
    opennsl_pkt_t *pkt, 
    void *cookie)
{
    onsl_drv_port_t *dport;
    int i;
    int rv;

    {
        struct ether_header * eth = (struct ether_header *) pkt->pkt_data->data;
        orc_debug("Receiving packet from ASIC port %d/%d: "
                        ETH_FORMAT " -> " ETH_FORMAT " :: (0x%.4x) %u bytes\n",
                        unit, pkt->rx_port,
                        ETH_ADDR_PRINT(eth->ether_shost),
                        ETH_ADDR_PRINT(eth->ether_dhost),
                        ntohs(eth->ether_type),
                        pkt->pkt_len);
    }

    for (i = 0; i < onsl_drv_ports_num; i++)
    {
        dport = &onsl_drv_ports[i];

        if (dport->drv_unit == unit && dport->drv_port == pkt->rx_port &&
            dport->user_port.index != ONSL_DRV_USER_PORT_INDEX_INVALID)
        {
            size_t header_len = 12;
            uint8_t *payload = pkt->pkt_data->data + header_len;
            int payload_offset = 0;
            size_t payload_len = pkt->pkt_len - header_len;

            if (pkt->rx_untagged != 0x01)
                payload_offset += 4;
            while (payload[payload_offset] == 0x81 && payload[payload_offset+1] == 0x00)
                payload_offset += 4;
            payload_len -= payload_offset;

            {
                struct ether_header * eth = (struct ether_header *) pkt->pkt_data->data;
                struct ether_header * eth2 = (struct ether_header *)(payload + payload_offset - header_len);
                orc_debug("Sending packet to port %s from ASIC: "
                                ETH_FORMAT " -> " ETH_FORMAT " :: (0x%.4x) %u bytes\n",
                                dport->user_port.name,
                                ETH_ADDR_PRINT(eth->ether_shost),
                                ETH_ADDR_PRINT(eth->ether_dhost),
                                ntohs(eth2->ether_type),
                                header_len + payload_len);
            }

            memmove(payload, payload + payload_offset, payload_len);
            rv = write(dport->user_port.fd, pkt->pkt_data->data, header_len + payload_len);
            return OPENNSL_RX_HANDLED_OWNED;
        }
    }

    COMPILER_REFERENCE(rv);

    return OPENNSL_RX_NOT_HANDLED;
}

static int onsl_drv_start_rx(port_t * ports[], int num_ports)
{
    int drv_unit;

    {
        orc_debug("Starting RX\n");
    }

    for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
    {
        OPENNSL_IF_ERROR_RETURN(opennsl_rx_register(
            drv_unit,
            "onsl_drv",
            onsl_drv_rx_cb,
            OPENNSL_RX_PRIO_MAX,
            NULL, OPENNSL_RCO_F_ALL_COS));
    }

    return 0;
}

static int onsl_drv_stop_rx()
{
    int drv_unit;

    {
        orc_debug("Stoping RX\n");
    }

    for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
    {
        OPENNSL_IF_ERROR_RETURN(opennsl_rx_unregister(
            drv_unit,
            onsl_drv_rx_cb,
            OPENNSL_RX_PRIO_MAX));
    }

    return 0;
}

static int onsl_drv_raw_port_enable(port_t * port)
{
    onsl_drv_port_t *dport = (onsl_drv_port_t *)port;

    OPENNSL_IF_ERROR_RETURN(opennsl_port_enable_set(dport->drv_unit, dport->drv_port, 1));

    return 0;
}

static int onsl_drv_raw_port_disable(port_t * port)
{
    onsl_drv_port_t *dport = (onsl_drv_port_t *)port;

    OPENNSL_IF_ERROR_RETURN(opennsl_port_enable_set(dport->drv_unit, dport->drv_port, 0));

    return 0;
}

static int _onsl_drv_port_vlan_set(onsl_drv_port_t *dport, opennsl_vlan_t vid)
{
    int drv_unit;
    opennsl_vlan_t old_vid;
    opennsl_pbmp_t pbmp;
    int rv;

    for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
    {
        rv = opennsl_vlan_create(drv_unit, vid);
    }

    OPENNSL_IF_ERROR_RETURN(opennsl_port_untagged_vlan_get(dport->drv_unit, dport->drv_port, &old_vid));
    OPENNSL_PBMP_PORT_SET(pbmp, dport->drv_port);
    rv = opennsl_vlan_port_remove(dport->drv_unit, old_vid, pbmp);
    rv = opennsl_vlan_port_add(dport->drv_unit, vid, pbmp, pbmp);
    OPENNSL_IF_ERROR_RETURN(opennsl_port_untagged_vlan_set(dport->drv_unit, dport->drv_port, vid));

    COMPILER_REFERENCE(rv);

    return 0;
}

static int onsl_drv_add_l3_v4_interface(
        port_t *port,
        u8 hw_mac[6],
        int mtu,
        u32 ipv4_addr,
        l3_intf_id_t * l3_intf_id
    )
{
    onsl_drv_port_t *dport = (onsl_drv_port_t *)port;
    opennsl_vlan_t vid;
    opennsl_l3_intf_t intf;
    int drv_unit;

    {
        orc_debug("Adding L3 Interface: mac=" ETH_FORMAT
                " ip=" IPV4_FORMAT
                " on port %s with mtu %d\n",
                ETH_ADDR_PRINT(hw_mac),
                IPV4_ADDR_PRINT(ipv4_addr),
                port->name,
                mtu);
    }

    /***
     *  TODO: decide how to handle vlans; short term expectation is that each
     *          interface will have its own unique vlan
     */
    vid = port->index + 1;

    /* vlan */
    OPENNSL_IF_ERROR_RETURN(_onsl_drv_port_vlan_set(dport, vid));

    /* l3_intf */
    opennsl_l3_intf_t_init(&intf);

    memcpy(intf.l3a_mac_addr, hw_mac, sizeof(opennsl_mac_t));
    intf.l3a_vid = vid;
    intf.l3a_mtu = mtu;
    intf.l3a_flags |= OPENNSL_L3_ADD_TO_ARL;

    for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
    {
    	OPENNSL_IF_ERROR_RETURN(opennsl_l3_intf_create(drv_unit, &intf));

        intf.l3a_flags |= OPENNSL_L3_WITH_ID;
        intf.l3a_flags |= OPENNSL_L3_REPLACE;
    }

#if 0 /* l3_host */
    /* l3_host */
    if (onsl_drv_cpu_l3_intf != -1)
    {
        opennsl_l3_host_t l3_host;

        opennsl_l3_host_t_init(&l3_host);

        l3_host.l3a_flags |= OPENNSL_L3_HIT | OPENNSL_L3_L2TOCPU | OPENNSL_L3_RPE;
        l3_host.l3a_ip_addr = ipv4_addr;
        l3_host.l3a_intf = onsl_drv_cpu_l3_intf;

        for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
        {
            OPENNSL_IF_ERROR_RETURN(opennsl_l3_host_add(drv_unit, &l3_host));
        }

        drv_l3_intf->l3a_ip_addr = l3_host.l3a_ip_addr;
    }
#endif /* l3_host */

    /* output */
    *l3_intf_id = intf.l3a_intf_id;

    return 0;
}

static int onsl_drv_update_l3_v4_interface(
        port_t *port,
        u8 hw_mac[6],
        int mtu,
        u32 ipv4_addr,
        l3_intf_id_t l3_intf_id
    )
{
    onsl_drv_port_t *dport = (onsl_drv_port_t *)port;
    opennsl_l3_intf_t intf;
    int drv_unit;

    {
        orc_debug("Adding L3 Interface: mac=" ETH_FORMAT
                " ip=" IPV4_FORMAT
                " on port %s with mtu %d\n",
                ETH_ADDR_PRINT(hw_mac),
                IPV4_ADDR_PRINT(ipv4_addr),
                port->name,
                mtu);
    }

    /* l3_intf */
    opennsl_l3_intf_t_init(&intf);

    intf.l3a_intf_id = l3_intf_id;

    OPENNSL_IF_ERROR_RETURN(opennsl_l3_intf_get(dport->drv_unit, &intf));

    memcpy(intf.l3a_mac_addr, hw_mac, sizeof(opennsl_mac_t));
    intf.l3a_mtu = mtu;
    intf.l3a_flags |= OPENNSL_L3_WITH_ID;
    intf.l3a_flags |= OPENNSL_L3_REPLACE;

    for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
    {
    	OPENNSL_IF_ERROR_RETURN(opennsl_l3_intf_create(drv_unit, &intf));

        intf.l3a_flags |= OPENNSL_L3_WITH_ID;
        intf.l3a_flags |= OPENNSL_L3_REPLACE;
    }

#if 0 /* l3_host */
    /* l3_host */
    if (onsl_drv_cpu_l3_intf != -1)
    {
        opennsl_l3_host_t l3_host;

        opennsl_l3_host_t_init(&l3_host);

        l3_host.l3a_ip_addr = drv_l3_intf->l3a_ip_addr;

        for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
        {
            OPENNSL_IF_ERROR_RETURN(opennsl_l3_host_delete(drv_unit, &l3_host));
        }

        opennsl_l3_host_t_init(&l3_host);

        l3_host.l3a_flags |= OPENNSL_L3_HIT | OPENNSL_L3_L2TOCPU | OPENNSL_L3_RPE;
        l3_host.l3a_ip_addr = ipv4_addr;
        l3_host.l3a_intf = onsl_drv_cpu_l3_intf;

        for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
        {
            OPENNSL_IF_ERROR_RETURN(opennsl_l3_host_add(drv_unit, &l3_host));
        }
    }
#endif /* l3_host */

    return 0;
}

static int onsl_drv_del_l3_interface(port_t * port, l3_intf_id_t l3_intf_id)
{
    onsl_drv_port_t *dport = (onsl_drv_port_t *)port;
    opennsl_l3_intf_t intf;
    int drv_unit;

    {
        orc_debug("Deleting L3 Interface by ID: %d\n", l3_intf_id);
    }

    /* l3_intf */
    opennsl_l3_intf_t_init(&intf);

    intf.l3a_intf_id = l3_intf_id;

    for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
    {
        OPENNSL_IF_ERROR_RETURN(opennsl_l3_intf_delete(drv_unit, &intf));
    }

#if 0 /* l3_host */
    /* l3_host */
    if (onsl_drv_cpu_l3_intf != -1)
    {
        opennsl_l3_host_t l3_host;

        opennsl_l3_host_t_init(&l3_host);

        l3_host.l3a_ip_addr = drv_l3_intf->l3a_ip_addr;

        for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
        {
            OPENNSL_IF_ERROR_RETURN(opennsl_l3_host_delete(drv_unit, &l3_host));
        }
    }
#endif /* l3_host */

    /* vlan */
    OPENNSL_IF_ERROR_RETURN(_onsl_drv_port_vlan_set(dport, 1));

    return 0;
}

static int onsl_drv_add_l3_v4_next_hop(
        port_t * port,
        l3_intf_id_t l3_intf_id,
        u8 next_hop_hw_mac[6],
        l3_next_hop_id_t * l3_next_hop_id
        )
{
    onsl_drv_port_t *dport = (onsl_drv_port_t *)port;
    opennsl_l3_intf_t intf;
    opennsl_l3_egress_t egr;
    opennsl_if_t if_id;
    uint32 flags;
    int drv_unit;

    {
        orc_debug("Adding L3 NextHop: next_hop_mac=" ETH_FORMAT
                " on L3 interface %d\n",
                ETH_ADDR_PRINT(next_hop_hw_mac),
                l3_intf_id);
    }

    opennsl_l3_intf_t_init(&intf);

    intf.l3a_intf_id = l3_intf_id;

    OPENNSL_IF_ERROR_RETURN(opennsl_l3_intf_get(dport->drv_unit, &intf));

    opennsl_l3_egress_t_init(&egr);

    memcpy (egr.mac_addr, next_hop_hw_mac, sizeof (opennsl_mac_t));
    egr.vlan = intf.l3a_vid;
    egr.intf = intf.l3a_intf_id;
    egr.port = dport->drv_port;
    flags = 0;

    for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
    {
        OPENNSL_IF_ERROR_RETURN(opennsl_l3_egress_create(drv_unit, flags, &egr, &if_id));

        flags |= OPENNSL_L3_WITH_ID;
    }

    *l3_next_hop_id = if_id;

    return 0;
}

static int onsl_drv_del_l3_next_hop(l3_next_hop_id_t l3_next_hop_id)
{
    opennsl_if_t if_id;
    int drv_unit;

    {
        orc_debug("Deleting L3 Next Hop by ID: %d(0x%08x)\n", l3_next_hop_id, l3_next_hop_id);
    }

    if_id = l3_next_hop_id;

    for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
    {
        OPENNSL_IF_ERROR_RETURN(opennsl_l3_egress_destroy(drv_unit, if_id));
    }

    return 0;
}

static int onsl_drv_add_l3_v4_route(u32 ip_dst, u32 netmask, l3_next_hop_id_t l3_next_hop_id)
{
    int drv_unit;

    {
        orc_debug("Adding L3 v4 route: " IPV4_FORMAT "/" IPV4_FORMAT
                " --> next_hop_id=%d(0x%08x)\n",
                IPV4_ADDR_PRINT(ip_dst),
                IPV4_ADDR_PRINT(netmask),
                l3_next_hop_id,
                l3_next_hop_id);
    }

    if (l3_next_hop_id == NEXT_HOP_KERNEL)
    {
        /* do nothing
         */
        return 0;
    }

    if (netmask == 0xffffffff)
    {
        opennsl_l3_host_t l3_host;

        opennsl_l3_host_t_init(&l3_host);

        l3_host.l3a_flags |= OPENNSL_L3_HIT;
        l3_host.l3a_ip_addr = ip_dst;
        l3_host.l3a_intf = l3_next_hop_id;

        for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
        {
            OPENNSL_IF_ERROR_RETURN(opennsl_l3_host_add(drv_unit, &l3_host));
        }
    }
    else
    {
        opennsl_l3_route_t l3_route;

        opennsl_l3_route_t_init(&l3_route);

        l3_route.l3a_flags |= OPENNSL_L3_HIT | OPENNSL_L3_REPLACE;
        l3_route.l3a_intf = (opennsl_if_t)l3_next_hop_id;
        l3_route.l3a_subnet = ip_dst;
        l3_route.l3a_ip_mask = netmask;

        for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
        {
            OPENNSL_IF_ERROR_RETURN(opennsl_l3_route_add(drv_unit, &l3_route));
        }
    }

    return 0;
}

static int onsl_drv_del_l3_v4_route(u32 ip_dst, u32 netmask, l3_next_hop_id_t l3_next_hop_id)
{
    int drv_unit;

    {
        orc_debug("Deleting L3 v4 route: " IPV4_FORMAT "/" IPV4_FORMAT
                " --> next_hop_id=%d(0x%08x)\n",
                IPV4_ADDR_PRINT(ip_dst),
                IPV4_ADDR_PRINT(netmask),
                l3_next_hop_id,
                l3_next_hop_id);
    }

    if (netmask == 0xffffffff) /* direct attach/host route */
    {
        opennsl_l3_host_t l3_host;

        opennsl_l3_host_t_init(&l3_host);

        l3_host.l3a_ip_addr = ip_dst;

        for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
        {
            OPENNSL_IF_ERROR_RETURN(opennsl_l3_host_delete(drv_unit, &l3_host));
        }
    }
    else
    {
        opennsl_l3_route_t l3_route;

        opennsl_l3_route_t_init(&l3_route);

        l3_route.l3a_subnet = ip_dst;
        l3_route.l3a_ip_mask = netmask;

        for (drv_unit = 0; drv_unit <= onsl_drv_max_unit; drv_unit++)
        {
            OPENNSL_IF_ERROR_RETURN(opennsl_l3_route_delete(drv_unit, &l3_route));
        }
    }

    return 0;
}

#if 0 /* not implemented */
void onsl_drv_log_onsl_drv_info()
{
}
#endif


/*****
 * Actual hooks into this driver; DRIVER_HOOKS
 * is the symbol that the main program looks for
 */


orc_driver_t DRIVER_HOOKS = {
    .init_driver = onsl_drv_init_driver,
    .discover_ports = onsl_drv_discover_ports,
    .tx_pkt = onsl_drv_tx_pkt,
    .start_rx = onsl_drv_start_rx,
    .stop_rx = onsl_drv_stop_rx,
    .raw_port_enable = onsl_drv_raw_port_enable,
    .raw_port_disable = onsl_drv_raw_port_disable,
    .add_l3_v4_interface = onsl_drv_add_l3_v4_interface,
    .update_l3_v4_interface = onsl_drv_update_l3_v4_interface,
    .del_l3_interface = onsl_drv_del_l3_interface,
    .add_l3_v4_next_hop = onsl_drv_add_l3_v4_next_hop,
    .del_l3_next_hop = onsl_drv_del_l3_next_hop,
    .add_l3_v4_route = onsl_drv_add_l3_v4_route,
    .del_l3_v4_route = onsl_drv_del_l3_v4_route,
#if 0 /* not implemented */
    .log_onsl_drv_info = onsl_drv_log_onsl_drv_info,
#endif
};
