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
#define MAX_ROUTERS 256 // Adjust this based on the maximum routers in your topology


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

// --- Node ---
// Represents a graph node for storing network topology details.
struct node {
    uint32_t subnet;         // Subnet address of the link
    uint32_t router_id;      // ID of the router advertising this subnet
    uint32_t neighbor_id;    // ID of the neighboring router
    uint32_t mask;           // Subnet mask
    uint32_t next_hop;       // Next hop IP address
    int seq;            // Sequence number for the advertisement
    struct node* next;  // Pointer to the next node in the list
};

/**
 * @brief Represents a single entry in the shortest path result.
 *
 * Each entry contains information about a subnet, its mask, the next hop,
 * and the outgoing interface.
 */
struct shortest_path_entry {
    uint32_t subnet;             // Destination subnet (IP prefix)
    uint32_t mask;               // Subnet mask
    uint32_t next_hop;           // Next hop IP address
    char interface[SR_IFACE_NAMELEN]; // Outgoing interface name
    struct shortest_path_entry* next; // Pointer to the next entry in the list
};

struct bfs_queue_entry {
    int distance;
    struct pwospf_router* router;
    struct pwospf_interface* first_hop_iface;  // Interface to use for this path
    uint32_t next_hop_ip;  // Next hop IP for this path
};


/**
 * @brief Represents the result of the BFS shortest path computation.
 *
 * This structure contains a list of shortest paths to all subnets in the network.
 */
struct shortest_path_result {
    struct shortest_path_entry* entries; // Linked list of shortest path entries
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
void send_pwospf_hello(struct sr_instance* sr);
void handle_pwospf_hello(struct sr_instance* sr, uint8_t* packet, char* interface);
void pwospf_check_on_neighbors(struct sr_instance* sr, time_t* last_lsu_time);
int validate_pwospf_packet(struct sr_instance* sr, struct ospfv2_hdr* ospf_hdr, unsigned int ospf_len);
void pwospf_handle_lsu(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
void read_static_routes(struct sr_instance* sr, struct pwospf_subsys* subsys);
void print_lsu_debug_info(uint32_t router_id, uint32_t neighbor_ip, uint32_t num_links, struct ospfv2_lsu* lsu_adv);
void print_topology(struct pwospf_subsys* subsys);
struct node* node_exists(uint32_t router_id, uint32_t subnet);
void create_rtable_entry(struct sr_instance *sr, uint32_t dest, uint32_t next_hop, uint32_t mask, char *iface);
struct sr_rt* lookup_routing_table(struct sr_instance* sr, uint32_t ip_target, uint32_t next_hop);
void recalculate_routing_table(struct sr_instance* sr);
bool route_already_implied(struct sr_instance* sr, uint32_t subnet, uint32_t mask);
void add_directly_connected_subnets(struct sr_instance* sr);
void update_rtable_entry(struct sr_instance* sr, struct sr_rt* entry, uint32_t next_hop, uint32_t mask, const char* iface);
struct sr_rt* lookup_route_by_subnet(struct sr_instance* sr, uint32_t subnet);
void pwospf_flood_lsu(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);
void pwospf_add_new_router_to_topology(struct pwospf_subsys* subsys, uint32_t router_id,
                                       struct ospfv2_lsu* lsu_adv, uint32_t num_links, uint32_t seq);
int topology_changed(struct pwospf_router* router_entry, struct ospfv2_lsu* lsu_adv, uint32_t num_links);
void pwospf_update_router_topology(struct pwospf_router* router_entry,
                                   struct ospfv2_lsu* lsu_adv, uint32_t num_links, uint32_t seq);
struct pwospf_router* pwospf_find_router_entry(struct pwospf_subsys* subsys, uint32_t router_id);

int pwospf_validate_lsu_packet(struct sr_instance* sr, struct pwospf_subsys* subsys,
                                struct ospfv2_hdr* ospf_hdr, uint32_t seq, char* interface);
void clear_non_direct_routes(struct sr_instance* sr);
bool is_valid_link(struct pwospf_router* router1, struct pwospf_interface* iface1,
                  struct pwospf_router* router2);
void pwospf_update_router_sequence_number(struct pwospf_router* router_entry, uint32_t seq);
void add_current_router_to_topology(struct pwospf_subsys* subsys);
void update_self_router_topology(struct pwospf_subsys* subsys, struct pwospf_interface* iface);
void print_shortest_paths(struct shortest_path_result* result);

void pwospf_send_lsu(struct sr_instance* sr, const char* exclude_iface);

// uint16_t checksum_pwospf(uint8_t* data, size_t length, size_t auth_offset, size_t auth_length);
uint16_t checksum_pwospf(uint16_t* buf, size_t count);
#endif /* SR_PWOSPF_H */