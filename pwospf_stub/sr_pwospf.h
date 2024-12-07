/*-----------------------------------------------------------------------------
 * file:  sr_pwospf.h
 * date:  Tue Nov 23 23:21:22 PST 2004 
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_PWOSPF_H
#define SR_PWOSPF_H

#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "sr_if.h"
#include "pwospf_protocol.h" // Ensure this header defines struct ospfv2_hdr

/* forward declare */
struct sr_instance;

/* pwospf constants */
#define PWOSPF_VERSION 2
#define PWOSPF_TYPE_HELLO 1
#define PWOSPF_TYPE_LSU 4
#define HELLO_INTERVAL 5
#define NEIGHBOR_TIMEOUT (3 * HELLO_INTERVAL)
#define LSUINT 30
#define LSU_TIMEOUT (3 * LSUINT)

/* -----------------------------------------------------------------
 * PWOSPF Data Structures
 * -----------------------------------------------------------------
 */

// --- Router ---
// Represents a single router in the PWOSPF topology.
struct pwospf_router {
    uint32_t router_id;       // Router ID, typically the IP address of the first interface.
    uint32_t area_id;         // Area ID (set to 0 for this project).
    uint16_t lsu_interval;    // Time interval (in seconds) between Link State Updates.
    uint16_t last_sequence;   // Last received sequence number from LSUs.
    struct pwospf_interface *interfaces; // List of interfaces on this router.
    struct pwospf_router *next;   // Pointer to the next router in the topology (linked list).
    time_t last_updated; // Timestamp for the last LSU received
};

// --- Neighbor ---
/* pwospf neighbor structure */
struct pwospf_neighbor {
    uint32_t router_id;           // Router ID of the neighbor
    uint32_t neighbor_ip;         // IP address of the neighbor
    uint32_t next_hop;            // IP address of the next hop
    time_t last_hello_received;   // Timestamp for the last HELLO message received
    struct pwospf_neighbor *next; // Linked list for neighbors
};

// --- Interface ---
// Represents a network interface on a router.
struct pwospf_interface {
    char name[SR_IFACE_NAMELEN];    // Interface name (e.g., "eth0").
    uint32_t ip;                   // IP address of the interface.
    uint32_t mask;                 // Subnet mask.
    uint16_t helloint;             // HELLO interval (default: 10 seconds).
    struct pwospf_neighbor neighbor; // Single neighbor attached to this interface.
    uint32_t next_hop;             // New field: IP address of the next hop.
    struct pwospf_interface* next; // Pointer to the next interface in the list.
};

struct pwospf_subsys
{
    uint32_t router_id;      // ID of the router, typically the IP of the first interface
    uint32_t area_id;        // Single OSPF area for this project (set to 0)
    uint16_t lsu_interval;   // Time interval between LSUs
    uint32_t seq;            // Sequence number for LSU packets
    struct pwospf_interface* interfaces; // Linked list of router interfaces
    struct pwospf_router* topology;      // Topology database (linked list)
    bool is_gw;              // Is this router a gateway router?

    pthread_t thread;        // HELLO thread
    pthread_mutex_t lock;    // Mutex lock for thread synchronization
};




int pwospf_init(struct sr_instance* sr);
void pwospf_print_subsys(struct pwospf_subsys* subsys);
void send_pwospf_hello(struct sr_instance* sr);
void handle_pwospf_hello(struct sr_instance* sr, uint8_t* packet, char* interface);
void pwospf_check_on_neighbors(struct sr_instance* sr, time_t* last_lsu_time);
int validate_pwospf_packet(struct sr_instance* sr, struct ospfv2_hdr* ospf_hdr, unsigned int ospf_len);
void pwospf_handle_lsu(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
void read_static_routes(struct sr_instance* sr, struct pwospf_subsys* subsys);
int validate_link(struct pwospf_subsys* subsys, uint32_t router_id, uint32_t subnet, uint32_t mask, uint32_t neighbor_id);
void update_topology_database(struct pwospf_subsys* subsys, uint32_t router_id, uint32_t seq, struct ospfv2_lsu* lsu_adv, uint32_t num_links);
void cleanup_topology_database(struct pwospf_subsys* subsys);
void print_lsu_debug_info(uint32_t router_id, uint32_t neighbor_ip, uint32_t num_links, struct ospfv2_lsu* lsu_adv);
void print_topology(struct pwospf_subsys* subsys);
void print_router_interfaces(struct pwospf_router* router);
void update_next_hop(struct pwospf_router* router, uint32_t received_from_ip, uint32_t sender_router_id);

void pwospf_update_neighbor(struct pwospf_interface* iface, uint32_t router_id, uint32_t neighbor_ip);
void pwospf_remove_timed_out_neighbors(struct pwospf_interface* iface);
void pwospf_send_lsu(struct sr_instance* sr, const char* exclude_iface);
int pwospf_validate_lsu(struct pwospf_subsys* subsys, uint32_t router_id, uint32_t seq);

// uint16_t checksum_pwospf(uint8_t* data, size_t length, size_t auth_offset, size_t auth_length);
uint16_t checksum_pwospf(uint16_t* buf, size_t count);
#endif /* SR_PWOSPF_H */