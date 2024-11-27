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

/* forward declare */
struct sr_instance;

/* pwospf constants */
#define PWOSPF_VERSION 2
#define PWOSPF_TYPE_HELLO 1
#define PWOSPF_TYPE_LSU 4
#define HELLO_INTERVAL 10
#define NEIGHBOR_TIMEOUT (3 * HELLO_INTERVAL)

/* pwospf neighbor structure */
struct pwospf_neighbor {
    uint32_t router_id;
    uint32_t neighbor_ip;
    time_t last_hello_received;
    struct pwospf_neighbor *next; // Linked list for neighbors
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
    uint32_t area_id; // Single OSPF area for this project (set to 0)
    struct pwospf_interface *interfaces; // Linked list of router interfaces

    /* -- thread and single lock for pwospf subsystem -- */
    pthread_t thread; // HELLO thread
    pthread_mutex_t lock; // Mutex lock for thread synchronization
};

int pwospf_init(struct sr_instance* sr);
void* pwospf_hello_thread(void* arg);
void pwospf_print_subsys(struct pwospf_subsys* subsys);
void pwospf_send_hello(struct sr_instance* sr, struct pwospf_interface* iface);
void pwospf_update_neighbor(struct pwospf_interface* iface, uint32_t router_id, uint32_t neighbor_ip);
void pwospf_remove_timed_out_neighbors(struct pwospf_interface* iface);
#endif /* SR_PWOSPF_H */
