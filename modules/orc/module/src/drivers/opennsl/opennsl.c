#include <sal/commdefs.h>
#include <opennsl/init.h>
#include <sal/driver.h>
#include <opennsl/error.h>
#include <opennsl/stat.h>
#include <opennsl/vlan.h>
#include <opennsl/pkt.h>
#include <opennsl/tx.h>
#include <opennsl/l2.h>
#include <shared/pbmp.h>

#include <netinet/if_ether.h>

#include "orc/utils.h"
#include "orc/orc_logger.h"
#include "orc/orc_driver.h"
#include "orc/tap_utils.h"

#define PREFIX "OPENNSL_DRV: "
//#define SWITCH_UNIT_NUM 0
#define DEFAULT_VLAN 1

int switch_unit_num = 0;

#if defined(DEBUG)
#define PRINTD(...) printf(__VA_ARGS__)
#else
#define PRINTD(...)
#endif

static const int internal_offset = 0; // local unit only

typedef struct {
    port_t port;
    int internal_index;
} internal_port_t;

char* hw_mac_to_str(opennsl_mac_t mac){
  int i;
  const int mac_length = 6;
  char* ret = malloc(sizeof(char) * mac_length * 3); // a mac address is represented as "11:22:33:44:55:66\0"
  
  for(i=0;i<6;i++){
    sprintf(ret + i*3, "%02X%c", mac[i], (i<5 ? ':' : '\0'));
  }

  return ret;
}

int opennsl_init_driver(orc_options_t * options, int argc, char * argv[]){
  //int opennsl_init_driver(){
  opennsl_error_t status;
  int ret;
  
  status = opennsl_driver_init();
  
  if(status != OPENNSL_E_NONE){
    printf(PREFIX "initializing the opennsl driver failed\n");
    return -1;
  }

  if(opennsl_attach_check(switch_unit_num) != OPENNSL_E_NONE){
    ret  = opennsl_attach(switch_unit_num, NULL, NULL, switch_unit_num);
    if(ret < 0){
      printf("Error at opennsl_attach: %s\n", opennsl_errmsg(ret));
      return -1;
    }
  }

  /*
  ret = opennsl_init(switch_unit_num);
  if(ret != OPENNSL_E_NONE){
    printf("Error: %s\n", opennsl_errmsg(ret));
    return -1;
  }
  */
  
  return 0;
}

int opennsl_discover_ports(port_t * ports[], int * num){
  opennsl_port_config_t pcfg;
  opennsl_error_t status;
  int count = -1, i, port_index;

  internal_port_t* oport;

  status = opennsl_port_config_get(switch_unit_num, &pcfg);
  if(status != OPENNSL_E_NONE){
    printf(PREFIX "retrieving the port config failed\n");
    return -1;
  }
    
  _SHR_PBMP_COUNT(pcfg.port, count);
  if(count <= 0){
    printf(PREFIX "retrieving the number of front panel ports failed\n");
    return -1;
  }
  
  for(i=0; i<count; i++){
    oport = malloc(sizeof(internal_port_t));
    
    if(oport == NULL){
	orc_err("Out of mem allocating ports\n");
	return -1;
    }
    
    oport->port.index = i + 1; // broadcom port numbering starts from 1, not 0
    oport->internal_index = i + internal_offset;
    ports[i] = (port_t*)oport;
  }

  *num = count;
  printf(PREFIX "number of front panel ports: %d\n", count);
  
  _SHR_PBMP_ITER(pcfg.port, port_index){
    int port_status, ret;

    ret = opennsl_port_enable_set(switch_unit_num, port_index, 1);

    if(ret != OPENNSL_E_NONE){
      printf("Error: %s\n", opennsl_errmsg(ret));
      return -1;
    }
    
    opennsl_port_link_status_get(switch_unit_num, port_index, &port_status);
    printf("orc%02d %d\n", port_index, port_status);
  }

  status = opennsl_vlan_port_add(switch_unit_num, DEFAULT_VLAN, pcfg.port, pcfg.port);
  if(status != OPENNSL_E_NONE){
    printf("Error at opennsl_vlan_port_add: %s\n", opennsl_errmsg(status));
    return -1;
  }

  return 0;
}

int set_addr_to_switch_ports(){
  static int addr_set;
  opennsl_port_config_t pcfg;
  int port_index;
  
  opennsl_port_config_get(switch_unit_num, &pcfg);
  
  if(addr_set == 0){
    addr_set = 1;

    printf("Assigning mac addresses\n");
    
    _SHR_PBMP_ITER(pcfg.port, port_index){
      char port_name[64];
      opennsl_l2_addr_t addr;
      opennsl_mac_t mac; 
      
      sprintf(port_name, "orc%02d", port_index);
      opennsl_l2_addr_t_init(&addr, mac, DEFAULT_VLAN);
      addr.flags = OPENNSL_L2_STATIC;
      
      // typedef uint8 opennsl_mac_t[6]
      // interface_name_to_hw_mac(char name[IFNAMSIZ], u8 hw_mac[6])
      // -> 'opennsl_mac_t' and 'hw_mac' are compatible
      interface_name_to_hw_mac(port_name, mac);
      printf("%s is assigned to port %s\n", hw_mac_to_str(mac), port_name);
      
      opennsl_l2_addr_add(switch_unit_num, &addr);
    }
  }
  else{
    ; // addresses already set, do nothing
  }

  return 0;
}

/********************** copy-pasted from the debug driver **************************/

int opennsl_tx_pkt(port_t *port, u8 *pkt, unsigned int len) {
  const static int min_ethernet_packet_size = 46;
  const static int ethernet_header_size = 14;

  set_addr_to_switch_ports();
  
  struct ether_header* eth = (struct ether_header*)pkt;
  int i, payload_size = len - ethernet_header_size;
  u8* payload = pkt + ethernet_header_size;

  if(len < min_ethernet_packet_size){
    u8* pkt_padded = malloc(sizeof(u8) * min_ethernet_packet_size);

    memcpy(pkt_padded, pkt, len);

    return opennsl_tx_pkt(port, pkt_padded, min_ethernet_packet_size);
  }
  
  if(eth->ether_type == 0xDD86){
    printf("Warning: sending IPv6 packets not supported!\n");
    return 0;
  }
  
  printf("Sending %d bytes of packet from port %s to ASIC\n", len, port->name);

  printf("Source Mac: ");
  for(i=0;i<6;i++){
    printf("%02X%s", eth->ether_shost[i], (i<5 ? ":" : ""));
  }
  printf("\n");

  printf("Destination Mac: ");
  for(i=0;i<6;i++){
    printf("%02X%s", eth->ether_dhost[i], (i<5 ? ":" : ""));
  }
  printf("\n");

  printf("Packet Type: %X\n", eth->ether_type);
  printf("Payload:\n");
  for(i=0;i<payload_size;i++){
    printf("%02X", payload[i]);
  }
  printf("\n");
  
  opennsl_pkt_blk_t* packet_data = (opennsl_pkt_blk_t*)malloc(sizeof(opennsl_pkt_blk_t));
  packet_data->data = pkt;

  opennsl_pkt_t* packet = (opennsl_pkt_t*)malloc(sizeof(opennsl_pkt_t));
  packet->blk_count = 1;
  //  packet->dest_port = port->index;
  //  packet->dest_port = 100;
  //  packet->src_port = 100;
  //  packet->tx_upbmp = 100;
  packet->pkt_len = len;
  packet->pkt_data = packet_data;
  packet->unit = switch_unit_num;
  packet->flags = OPENNSL_TX_ETHER;

  printf("calling opennsl_tx...\n");
  int ret = opennsl_tx(switch_unit_num, packet, NULL);
  printf("...returned\n");
  
  if(!OPENNSL_SUCCESS(ret)){
    printf("Error: %s\n", opennsl_errmsg(ret));
    return -1;
  }

  return 0;
}

int debug_start_rx(port_t * ports[], int num_ports)
{
    printf(PREFIX "Fake starting RX\n");

    return 0;
}

int debug_stop_rx()
{
    printf(PREFIX "Fake stoping RX\n");

    return 0;
}

int debug_add_l3_v4_interface(
        port_t *port,
        u8 hw_mac[6],
        int mtu,
        u32 ipv4_addr,
        l3_intf_id_t * l3_intf_id
    )
{
  /*
  debug_port_t * dport = (debug_port_t *) port;
    printf(PREFIX "Fake adding L3 Interface: mac=" ETH_FORMAT
            " ip=" IPV4_FORMAT
            " on port %s with mtu %d\n",
            ETH_ADDR_PRINT(hw_mac),
            IPV4_ADDR_PRINT(ipv4_addr),
            port->name,
            mtu);
    *l3_intf_id = dport -> internal_index;
    port -> l3_intf_id = *l3_intf_id;
  */
  

    // a real driver would cache the l3_intf_id here for something
    // useful
    return 0;
}

int debug_del_l3_interface(port_t * port, l3_intf_id_t l3_intf_id)
{
    printf(PREFIX "Fake deleting L3 Interface by ID: %d\n", l3_intf_id);

    // a real driver would reclaim state here
    return 0;
}

int debug_add_l3_v4_next_hop(
        port_t * port,
        l3_intf_id_t l3_intf_id,
        u8 next_hop_hw_mac[6],
        l3_next_hop_id_t * l3_next_hop_id
        )
{
  /*
    static int NEXT_HOP_ID = 0;
    printf(PREFIX "Fake adding L3 NextHop: next_hop_mac=" ETH_FORMAT
            " on L3 interface %d\n",
            ETH_ADDR_PRINT(next_hop_hw_mac),
            l3_intf_id);
    *l3_next_hop_id = NEXT_HOP_ID++;
    */

    // a real driver would cache the l3_next_hop_id here for something
    // useful
    return 0;
}

int debug_del_l3_next_hop(l3_next_hop_id_t l3_next_hop_id)
{
    printf(PREFIX "Fake deleting L3 Next Hop by ID: %d\n", l3_next_hop_id);

    // a real driver would reclaim state here
    return 0;
}

int debug_add_l3_v4_route(u32 ip_dst, u32 netmask, l3_next_hop_id_t l3_next_hop_id)
{
  /*
    printf(PREFIX "Fake adding L3 v4 route: " IPV4_FORMAT "/" IPV4_FORMAT
            " --> next_hop_id=%d\n",
            IPV4_ADDR_PRINT(ip_dst),
            IPV4_ADDR_PRINT(netmask),
            l3_next_hop_id);
  */
    return 0;
}

int debug_del_l3_v4_route(u32 ip_dst, u32 netmask, l3_next_hop_id_t l3_next_hop_id)
{
  /*
  printf(PREFIX "Fake deleting L3 v4 route: " IPV4_FORMAT "/" IPV4_FORMAT
            " --> next_hop_id=%d\n",
            IPV4_ADDR_PRINT(ip_dst),
            IPV4_ADDR_PRINT(netmask),
            l3_next_hop_id);
  */
    return 0;
}

/********************** copy-pasted from the debug driver: ends here **************************/

orc_driver_t DRIVER_HOOKS = {
    .init_driver = opennsl_init_driver,
    .discover_ports = opennsl_discover_ports,
    .tx_pkt = opennsl_tx_pkt,
    .start_rx = debug_start_rx,
    .stop_rx = debug_stop_rx,
    .add_l3_v4_interface = debug_add_l3_v4_interface,
    .del_l3_interface = debug_del_l3_interface,
    .add_l3_v4_next_hop = debug_add_l3_v4_next_hop,
    .del_l3_next_hop = debug_del_l3_next_hop,
    .add_l3_v4_route    = debug_add_l3_v4_route,
    .del_l3_v4_route    = debug_del_l3_v4_route,
};

#if defined(DEBUG)
// main() appears only in debug builds

main(){
  opennsl_init_driver();
  opennsl_discover_ports();
}

#endif
