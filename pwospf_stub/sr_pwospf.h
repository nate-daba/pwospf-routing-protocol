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
#include <time.h>

#include "sr_if.h"
#include "pwospf_protocol.h" // Ensure this header defines struct ospfv2_hdr

/* forward declare */
struct sr_instance;

/* pwospf constants */
#define PWOSPF_VERSION 2
#define PWOSPF_TYPE_HELLO 1
#define PWOSPF_TYPE_LSU 4
#define HELLO_INTERVAL 10
#define NEIGHBOR_TIMEOUT (3 * HELLO_INTERVAL)
#define LSUINT 30

/* pwospf lsu link structure */
struct pwospf_lsu_link {
    uint32_t link_id;   // Subnet IP address
    uint32_t link_data; // Subnet mask
    uint8_t  type;      // Link type (e.g., point-to-point, stub)
    uint8_t  metric;    // Link cost (e.g., 1 for all links)
};


/* pwospf neighbor structure */
struct pwospf_neighbor {
    uint32_t router_id;
    uint32_t neighbor_ip;
    time_t last_hello_received;
    struct pwospf_neighbor *next; // Linked list for neighbors
};

/* pwospf lsu packet structure */
struct pwospf_lsu {
    uint32_t seq;       // Sequence number
    uint32_t num_links; // Number of advertised links
    struct pwospf_lsu_link links[]; // Variable length array of links
};

/* pwospf interface structure */
struct pwospf_interface {
    char name[SR_IFACE_NAMELEN];     // Name of the interface (e.g., "eth0")
    uint32_t ip;                      // IP address of the interface
    uint32_t mask;                    // Subnet mask
    uint16_t helloint;                // HELLO interval (default: 10 seconds)
    struct pwospf_neighbor* neighbors; // List of neighbors reachable via this interface
    struct pwospf_interface* next;    // Pointer to the next interface (linked list)
};

struct pwospf_subsys
{
    /* -- pwospf subsystem state variables here -- */
    uint32_t router_id; // ID of the router, typically the IP of the first interface
    uint32_t area_id;   // Single OSPF area for this project (set to 0)
    struct pwospf_interface *interfaces; // Linked list of router interfaces

    uint32_t seq;       // Sequence number for LSU packets

    struct pwospf_topology_entry* topology; // Topology database (linked list)

    /* -- thread and single lock for pwospf subsystem -- */
    pthread_t thread;       // HELLO thread
    pthread_mutex_t lock;   // Mutex lock for thread synchronization
};

/* Link State Advertisement (LSA) structure */
struct pwospf_lsa {
    uint32_t subnet;     // Subnet number of the link
    uint32_t mask;       // Subnet mask of the link
    uint32_t router_id;  // Router ID of the neighbor on the link (0 if no neighbor)
};

/* Topology database entry */
struct pwospf_topology_entry {
    uint32_t router_id;                 // Router ID of the entry
    uint32_t last_seq;                  // Last sequence number received from this router
    uint32_t num_links;                 // Number of LSAs advertised by this router
    struct pwospf_lsa* advertisements;  // Dynamically allocated array of LSAs
    time_t last_update;                 // Timestamp of the last received LSU
    struct pwospf_topology_entry* next; // Pointer to the next entry in the list
};

int pwospf_init(struct sr_instance* sr);
void pwospf_print_subsys(struct pwospf_subsys* subsys);
void pwospf_send_hello(struct sr_instance* sr, struct pwospf_interface* iface);
void pwospf_update_neighbor(struct pwospf_interface* iface, uint32_t router_id, uint32_t neighbor_ip);
void pwospf_remove_timed_out_neighbors(struct pwospf_interface* iface);
void pwospf_send_lsu(struct sr_instance* sr);
int pwospf_validate_lsu(struct pwospf_subsys* subsys, uint32_t router_id, uint32_t seq);
void pwospf_handle_lsu(struct sr_instance* sr, struct ospfv2_hdr* ospf_hdr, uint8_t* packet, unsigned int len, char* interface);
int validate_pwospf_packet(struct sr_instance* sr, struct ospfv2_hdr* ospf_hdr);
// uint16_t checksum_pwospf(uint8_t* data, size_t length, size_t auth_offset, size_t auth_length);
uint16_t checksum_pwospf(uint16_t* buf, size_t count);
#endif /* SR_PWOSPF_H */
