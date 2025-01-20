/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "sr_pwospf.h"
#include "pwospf_protocol.h"
#include "sr_if.h"
#include "sr_router.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "stdbool.h"    
#include <limits.h> // Include limits.h for INT_MAX


/* -- declaration of main thread function for pwospf subsystem --- */
static void* pwospf_run_thread(void* arg);

struct node *nodes = NULL;

/**
 * @brief Initializes the PWOSPF subsystem for a given router instance.
 *
 * This function allocates and configures the PWOSPF subsystem data structures,
 * including interfaces, topology, and threading. It also spawns the PWOSPF
 * subsystem thread to handle HELLO and LSU functionality.
 *
 * Steps performed:
 * - Allocates and initializes the `pwospf_subsys` structure.
 * - Builds a list of PWOSPF interfaces from the router's interface list.
 * - Reads and processes any static routes to determine if this router is a gateway.
 * - Creates and starts the PWOSPF thread (responsible for periodic HELLO and LSU).
 * - Adds the current router to the PWOSPF topology database.
 * - Adds directly connected subnets to the routing table.
 * - Prints the updated routing table for debugging/verification.
 *
 * @param sr Pointer to the router instance (`struct sr_instance`).
 * @return int Returns 0 on successful initialization.
 */

int pwospf_init(struct sr_instance* sr) {
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct pwospf_subsys));
    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);

    // Initialize the PWOSPF subsystem
    struct pwospf_subsys* subsys = sr->ospf_subsys;
    subsys->router_id = sr->if_list ? sr->if_list->ip : 0; // Use 0th interface IP or fallback
    subsys->area_id = 0; // Single area
    subsys->interfaces = NULL; // Initialize interfaces
    subsys->topology = NULL; // Initialize topology
    subsys->seq = 0; // Sequence number for LSUs
    subsys->lsu_interval = LSUINT; // Default LSU interval (30s)
    subsys->is_gw = false; // Default to non-gateway

    // Populate the PWOSPF interface list
    struct sr_if* iface = sr->if_list;
    struct pwospf_interface** pwospf_iface_ptr = &(subsys->interfaces);
    while (iface) {
        struct pwospf_interface* pwospf_iface = (struct pwospf_interface*)malloc(sizeof(struct pwospf_interface));
        strncpy(pwospf_iface->name, iface->name, SR_IFACE_NAMELEN);
        pwospf_iface->ip = iface->ip;
        pwospf_iface->mask = iface->mask;
        pwospf_iface->helloint = HELLO_INTERVAL;

        // Initialize the neighbor
        pwospf_iface->neighbor.router_id = 0; // No neighbor initially
        pwospf_iface->neighbor.neighbor_ip = 0;
        pwospf_iface->neighbor.last_hello_received = 0;

        pwospf_iface->next = NULL;

        *pwospf_iface_ptr = pwospf_iface;
        pwospf_iface_ptr = &(pwospf_iface->next);
        iface = iface->next;
    }

    // Read and process static routes
    read_static_routes(sr, subsys);

    // Start the thread subsystem
    if (pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr) != 0) {
        perror("pthread_create");
        assert(0);
    }

    printf("PWOSPF subsystem initialized with Router ID: %s\n",
           inet_ntoa(*(struct in_addr*)&subsys->router_id));

    // add the current router to the topology
    add_current_router_to_topology(subsys);

    // Add directly connected subnets to the routing table
    add_directly_connected_subnets(sr);

    // Print routing table
    sr_print_routing_table(sr);

    return 0;
}

/**
 * @brief Adds the current router (as defined by the PWOSPF subsystem) to the topology database.
 *
 * This function allocates a new `pwospf_router` structure corresponding to the
 * current router, replicates its interfaces, and prepends the new router entry
 * to the subsystem's linked-list of routers (the topology).
 *
 * Steps performed:
 * - Allocates memory for a new `pwospf_router` and initializes it with the
 *   current router's ID, area, and LSU interval.
 * - Clones each `pwospf_interface` from the subsystem's interface list into
 *   the newly allocated router entry.
 * - Inserts the new router at the head of the topology linked list (`subsys->topology`).
 * - Logs a message indicating that the current router has been added.
 *
 * @param subsys Pointer to the PWOSPF subsystem.
 *               Must not be NULL, or no action is taken.
 */
void add_current_router_to_topology(struct pwospf_subsys* subsys) {
    if (!subsys) return;

    struct pwospf_router* current_router = malloc(sizeof(struct pwospf_router));
    if (!current_router) {
        perror("[Error] Failed to allocate memory for current router");
        return;
    }

    memset(current_router, 0, sizeof(struct pwospf_router));
    current_router->router_id = subsys->router_id;
    current_router->area_id = subsys->area_id;
    current_router->lsu_interval = subsys->lsu_interval;

    // Populate interfaces
    struct pwospf_interface* iface = subsys->interfaces;
    while (iface) {
        struct pwospf_interface* new_iface = malloc(sizeof(struct pwospf_interface));
        if (!new_iface) {
            perror("[Error] Failed to allocate memory for interface");
            continue;
        }
        memcpy(new_iface, iface, sizeof(struct pwospf_interface));
        new_iface->next = current_router->interfaces;
        current_router->interfaces = new_iface;

        iface = iface->next;
    }

    // Add to the topology
    current_router->next = subsys->topology;
    subsys->topology = current_router;

    printf("[Topology] Current router added to topology: Router ID: %u\n", current_router->router_id);
}
/**
 * @brief Acquires the mutex lock associated with the PWOSPF subsystem.
 *
 * This function wraps a call to `pthread_mutex_lock()` on the subsystem's `lock`.
 * If the lock acquisition fails, an assertion triggers, terminating the program.
 *
 * @param subsys Pointer to the PWOSPF subsystem whose lock is to be acquired.
 */

void pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock) )
    { assert(0); }
} 

/**
 * @brief Releases the mutex lock associated with the PWOSPF subsystem.
 *
 * This function wraps a call to `pthread_mutex_unlock()` on the subsystem's `lock`.
 * If the unlock operation fails, an assertion triggers, terminating the program.
 *
 * @param subsys Pointer to the PWOSPF subsystem whose lock is to be released.
 */

void pwospf_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
}

/**
 * @brief Main thread function for the PWOSPF subsystem.
 *
 * This function runs in an infinite loop to handle periodic PWOSPF tasks:
 * - Sends HELLO messages at a fixed interval.
 * - Checks for neighbor timeouts and removes inactive neighbors.
 * - Periodically sends Link State Update (LSU) packets when the
 *   configured interval (`LSUINT`) has elapsed.
 *
 * The function locks the PWOSPF subsystem (`pwospf_lock`) before performing
 * these operations and unlocks it (`pwospf_unlock`) once done. Finally, it
 * sleeps for `HELLO_INTERVAL` seconds before repeating.
 *
 * @param arg Pointer to the router instance (`struct sr_instance`), passed
 *            when creating the thread.
 * @return Returns `NULL`, though this thread never exits under normal conditions.
 */
static void* pwospf_run_thread(void* arg) {
    struct sr_instance* sr = (struct sr_instance*)arg;
    time_t last_lsu_time = time(NULL); // Initialize last LSU time

    while (1) {
        /* -- PWOSPF subsystem functionality should start here! -- */
        pwospf_lock(sr->ospf_subsys);

        // Send periodic HELLO messages
        printf("Sending HELLO messages.\n");
        send_pwospf_hello(sr);

        // Check for timed-out neighbors
        printf("Checking neighbors for timeouts.\n");
        pwospf_check_on_neighbors(sr, &last_lsu_time);

        // Check if it's time to send a periodic LSU
        time_t now = time(NULL);
        if (difftime(now, last_lsu_time) >= LSUINT) {
            printf("Sending periodic LSU.\n");
            pwospf_send_lsu(sr, NULL); // Send LSU
            last_lsu_time = now; // Reset the LSU timer
        }

        pwospf_unlock(sr->ospf_subsys);

        // Sleep for HELLO_INTERVAL seconds
        sleep(HELLO_INTERVAL);
    }

    return NULL;
}

/**
 * @brief Validates a PWOSPF packet (either HELLO or LSU) against basic OSPF checks.
 *
 * This function checks the PWOSPF version, area ID, authentication fields, and
 * verifies the checksum based on the packet type (HELLO or LSU). If any check
 * fails, the packet is considered invalid and should be dropped.
 *
 * Validation Steps:
 * 1. Check PWOSPF version and area ID against expected values.
 * 2. Reject packets with unsupported authentication.
 * 3. Compute and compare the packet's checksum:
 *    - For HELLO: a fixed-size checksum over the OSPF header.
 *    - For LSU: a length-based, aligned checksum over the entire OSPF payload.
 *
 * @param sr        Pointer to the main router instance.
 * @param ospf_hdr  Pointer to the PWOSPF header within the packet.
 * @param ospf_len  Length of the PWOSPF portion of the packet (bytes).
 * @return int      Returns 1 if the packet is valid, 0 if invalid or unsupported.
 */
int validate_pwospf_packet(struct sr_instance* sr, struct ospfv2_hdr* ospf_hdr, unsigned int ospf_len) {
    assert(sr);
    assert(ospf_hdr);

    // Validate OSPF header fields common to all packet types
    if (ospf_hdr->version != PWOSPF_VERSION) {
        printf("Dropped PWOSPF packet: Unsupported version %d\n", ospf_hdr->version);
        return 0;
    }

    if (ospf_hdr->aid != sr->ospf_subsys->area_id) {
        printf("Dropped PWOSPF packet: Area ID mismatch\n");
        return 0;
    }

    if (ospf_hdr->autype != 0 || ospf_hdr->audata != 0) {
        printf("Dropped PWOSPF packet: Unsupported authentication\n");
        return 0;
    }

    // Verify checksum based on packet type
    uint16_t original_csum = ospf_hdr->csum; // Save the original checksum
    ospf_hdr->csum = 0;                      // Set checksum field to 0 for calculation

    if (ospf_hdr->type == PWOSPF_TYPE_HELLO) {

        // Use the fixed checksum calculation for HELLO packets
        uint8_t aligned_hdr[sizeof(struct ospfv2_hdr)];
        memcpy(aligned_hdr, ospf_hdr, sizeof(struct ospfv2_hdr));
        uint16_t computed_csum = checksum_pwospf((uint16_t*)aligned_hdr, sizeof(struct ospfv2_hdr) / 2);

        if (original_csum != computed_csum) {
            printf("Dropped PWOSPF HELLO packet: Checksum verification failed\n");
            printf("  Original Checksum: 0x%04x\n", ntohs(original_csum));
            printf("  Computed Checksum: 0x%04x\n", computed_csum);
            return 0;
        }
    } else if (ospf_hdr->type == PWOSPF_TYPE_LSU) {

        // Allocate aligned buffer for LSU checksum calculation
        size_t aligned_len = ospf_len + (ospf_len % 2); // Ensure even length
        uint8_t* aligned_buf = (uint8_t*)malloc(aligned_len);
        if (!aligned_buf) {
            perror("Failed to allocate memory for checksum buffer");
            return 0;
        }

        // Copy the OSPF payload into the aligned buffer
        memcpy(aligned_buf, ospf_hdr, ospf_len);

        // Pad with zero if the payload length is odd
        if (ospf_len % 2 != 0) {
            aligned_buf[ospf_len] = 0;
        }

        // Calculate the checksum
        uint16_t computed_csum = checksum_pwospf((uint16_t*)aligned_buf, aligned_len / 2);

        free(aligned_buf); // Free the allocated buffer

        if (original_csum != computed_csum) {
            printf("Dropped PWOSPF LSU packet: Checksum verification failed\n");
            printf("  Original Checksum: 0x%04x\n", ntohs(original_csum));
            printf("  Computed Checksum: 0x%04x\n", computed_csum);
            return 0;
        }
    } else {
        printf("Dropped PWOSPF packet: Unsupported type %d\n", ospf_hdr->type);
        return 0;
    }

    ospf_hdr->csum = original_csum; // Restore original checksum
    return 1; // Valid packet
}

/**
 * @brief Sends PWOSPF HELLO packets on all active PWOSPF interfaces.
 *
 * This function builds and broadcasts a HELLO packet to the AllSPFRouters
 * multicast address (`224.0.0.5`) for each interface in the PWOSPF subsystem.
 * Steps performed include:
 * 1. Constructing Ethernet and IP headers.
 * 2. Setting up the PWOSPF HELLO header (OSPF protocol number, router ID, etc.).
 * 3. Computing and inserting the OSPF checksum.
 * 4. Sending the packet via `sr_send_packet` on each interface.
 *
 * @param sr Pointer to the main router instance (`struct sr_instance`).
 */
void send_pwospf_hello(struct sr_instance* sr) {
    assert(sr);

    struct pwospf_interface* iface = sr->ospf_subsys->interfaces;
    while (iface) {
        assert(iface);

        size_t packet_len = sizeof(struct sr_ethernet_hdr) +
                            sizeof(struct ip) +
                            sizeof(struct ospfv2_hdr) +
                            sizeof(struct ospfv2_hello_hdr);

        uint8_t* packet = (uint8_t*)malloc(packet_len);
        memset(packet, 0, packet_len);

        // Construct Ethernet header
        struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)packet;
        memset(eth_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN); // Broadcast
        struct sr_if* sr_iface = sr_get_interface(sr, iface->name);
        memcpy(eth_hdr->ether_shost, sr_iface->addr, ETHER_ADDR_LEN);
        eth_hdr->ether_type = htons(ETHERTYPE_IP);

        // Construct IP header
        struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
        ip_hdr->ip_v = 4;
        ip_hdr->ip_hl = 5;
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(packet_len - sizeof(struct sr_ethernet_hdr));
        ip_hdr->ip_id = 0;
        ip_hdr->ip_off = 0;
        ip_hdr->ip_ttl = 64;
        ip_hdr->ip_p = 89; // OSPF Protocol
        ip_hdr->ip_src.s_addr = iface->ip;
        ip_hdr->ip_dst.s_addr = inet_addr("224.0.0.5"); // AllSPFRouters
        ip_hdr->ip_sum = checksum(ip_hdr, ip_hdr->ip_hl * 4);

        // Construct PWOSPF header
        struct ospfv2_hdr* ospf_hdr = (struct ospfv2_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
        ospf_hdr->version = PWOSPF_VERSION;
        ospf_hdr->type = PWOSPF_TYPE_HELLO;
        ospf_hdr->len = htons(sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr));
        ospf_hdr->rid = sr->ospf_subsys->router_id;
        ospf_hdr->aid = 0; // Single area
        ospf_hdr->autype = 0;
        ospf_hdr->audata = 0;

        // OSPF checksum calculation
        ospf_hdr->csum = 0; // Clear for checksum calculation

        size_t ospf_len = sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr);
        size_t aligned_len = ospf_len + (ospf_len % 2); // Ensure even length
        uint8_t* aligned_buf = (uint8_t*)malloc(aligned_len);
        if (!aligned_buf) {
            perror("Failed to allocate memory for checksum buffer");
            return;
        }

        memcpy(aligned_buf, ospf_hdr, ospf_len);
        if (ospf_len % 2 != 0) {
            aligned_buf[ospf_len] = 0; // Add padding
        }

        ospf_hdr->csum = checksum_pwospf((uint16_t*)aligned_buf, aligned_len / 2);
        free(aligned_buf);

        // Construct HELLO header
        struct ospfv2_hello_hdr* hello_hdr = (struct ospfv2_hello_hdr*)(packet + sizeof(struct sr_ethernet_hdr) +
                                                                        sizeof(struct ip) +
                                                                        sizeof(struct ospfv2_hdr));
        hello_hdr->nmask = iface->mask;
        hello_hdr->helloint = htons(HELLO_INTERVAL);

        // Send the packet
        sr_send_packet(sr, packet, packet_len, sr_iface->name);

        // printf("Sent HELLO packet from interface: %s (IP: %s)\n",
        //     sr_iface->name,
        //     inet_ntoa(*(struct in_addr*)&iface->ip));

        free(packet); // Free allocated memory
        iface = iface->next; // Move to the next interface
    }
}

/**
 * @brief Processes an incoming PWOSPF HELLO packet and updates neighbor information.
 *
 * This function is called when a PWOSPF HELLO packet arrives on a specific interface.
 * It performs the following steps:
 * 1. Validates the receiving interface.
 * 2. Verifies the network mask in the HELLO header matches the interface's mask.
 * 3. Extracts the neighbor's router ID and IP address.
 * 4. Updates (or replaces) the neighbor record in the corresponding `pwospf_interface`.
 * 5. Triggers a Link State Update (LSU) if a new neighbor is discovered.
 * 6. Updates the current router entry in the topology and recalculates the routing table.
 *
 * @param sr         Pointer to the main router instance (`struct sr_instance`).
 * @param packet     Pointer to the raw packet data containing Ethernet, IP, OSPF, and HELLO headers.
 * @param interface  The name of the interface on which the HELLO packet was received.
 */
void handle_pwospf_hello(struct sr_instance* sr, uint8_t* packet, char* interface) {
    assert(sr);
    assert(packet);
    assert(interface);

    // Parse headers
    struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
    struct ospfv2_hdr* ospf_hdr = (struct ospfv2_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + (ip_hdr->ip_hl * 4));
    struct ospfv2_hello_hdr* hello_hdr = (struct ospfv2_hello_hdr*)((uint8_t*)ospf_hdr + sizeof(struct ospfv2_hdr));

    // Validate the interface
    struct sr_if* iface = sr_get_interface(sr, interface);
    if (!iface) {
        printf("Invalid interface: %s\n", interface);
        return;
    }
    // Find corresponding PWOSPF interface
    struct pwospf_interface* pwospf_iface = sr->ospf_subsys->interfaces;
    while (pwospf_iface) {
        if (pwospf_iface->ip == iface->ip) {
            // Validate network mask consistency
            if (hello_hdr->nmask != pwospf_iface->mask) {
                printf("Dropped PWOSPF HELLO packet: Network mask mismatch\n");
                return;
            }

            // Extract neighbor details
            uint32_t router_id = ospf_hdr->rid;
            uint32_t neighbor_ip = ip_hdr->ip_src.s_addr;

            char router_id_str[INET_ADDRSTRLEN];
            char neighbor_ip_str[INET_ADDRSTRLEN];

            // Safely convert to string using inet_ntop
            if (!inet_ntop(AF_INET, &router_id, router_id_str, INET_ADDRSTRLEN)) {
                perror("Failed to convert Router ID to string");
                return;
            }
            if (!inet_ntop(AF_INET, &neighbor_ip, neighbor_ip_str, INET_ADDRSTRLEN)) {
                perror("Failed to convert Neighbor IP to string");
                return;
            }

            // Update or replace the single neighbor
            struct pwospf_neighbor* neighbor = &pwospf_iface->neighbor;
            // check if topology has changed by checking if the neighbor is new or updated
            if (neighbor->router_id != 0 && neighbor->router_id == router_id) {
                // Update existing neighbor
                neighbor->neighbor_ip = neighbor_ip;
                neighbor->last_hello_received = time(NULL);
                printf("Updated neighbor: Router ID: %s, Neighbor IP: %s\n",
                       router_id_str, neighbor_ip_str);
            } else {
                // Replace with new neighbor
                neighbor->router_id = router_id;
                neighbor->neighbor_ip = neighbor_ip;
                neighbor->last_hello_received = time(NULL);
                printf("Rejoice!! Added new neighbor: Router ID: %s, Neighbor IP: %s\n",
                       router_id_str, neighbor_ip_str);
                // Flood LSU
                printf("Initiating Link State Update due to new neighbor.\n");
                pwospf_send_lsu(sr, interface);
            }
            pwospf_iface->next_hop = neighbor_ip;
            // update current router in the topology with the updated neighbor info
            // Update the current router in the topology with the updated neighbor info
            update_self_router_topology(sr->ospf_subsys, pwospf_iface);
            print_topology(sr->ospf_subsys);
            // recalculate routing table
            recalculate_routing_table(sr);
            return;
        }
        pwospf_iface = pwospf_iface->next;
    }

    printf("No matching PWOSPF interface for HELLO packet received on %s\n", interface);
}

/**
 * @brief Updates the topology entry of the local router (`subsys->router_id`) with new or modified interface information.
 *
 * This function searches the PWOSPF subsystem's topology for the local router (identified
 * by `subsys->router_id`). Once found, it tries to locate an interface matching the IP
 * and mask of the provided `iface`. If a match is found, it updates the neighbor and
 * next-hop data for that interface. If no match is found, a new interface entry is
 * dynamically allocated and prepended to the local router's interface list.
 *
 * Steps performed:
 * 1. Locate the local router in the topology (matching `subsys->router_id`).
 * 2. Scan the local router's interface list to find a matching IP/mask.
 * 3. If matched, update the neighbor fields and `next_hop`.
 * 4. If no match, allocate a new interface, copy relevant fields, and insert it into the list.
 * 5. If the local router is not present in the topology, log a message and return.
 *
 * @param subsys Pointer to the PWOSPF subsystem containing the topology database.
 * @param iface  Pointer to the interface whose updates (neighbor info, next hop, etc.)
 *               should be reflected in the local router's topology entry.
 */
void update_self_router_topology(struct pwospf_subsys* subsys, struct pwospf_interface* iface) {
    assert(subsys);
    assert(iface);

    struct pwospf_router* router = subsys->topology;

    // Find the self-router entry in the topology
    while (router) {
        if (router->router_id == subsys->router_id) {
            struct pwospf_interface* current_iface = router->interfaces;

            // Traverse the interface list to find a match
            while (current_iface) {
                if (current_iface->ip == iface->ip && current_iface->mask == iface->mask) {
                    // Update the neighbor information and next hop
                    current_iface->neighbor.router_id = iface->neighbor.router_id;
                    current_iface->neighbor.neighbor_ip = iface->neighbor.neighbor_ip;
                    current_iface->neighbor.last_hello_received = iface->neighbor.last_hello_received;
                    current_iface->next_hop = iface->next_hop; // Ensure next hop is correctly updated

                    printf("[Topology Update] Updated self-router's topology for interface %s.\n", iface->name);
                    return;
                }
                current_iface = current_iface->next;
            }

            // If no match found, add the updated interface to the self-router's topology
            struct pwospf_interface* new_iface = malloc(sizeof(struct pwospf_interface));
            if (!new_iface) {
                perror("Failed to allocate memory for interface update.");
                return;
            }
            // memcpy(new_iface, iface, sizeof(struct pwospf_interface));
            // new_iface->next_hop = iface->neighbor.neighbor_ip; // Set next hop correctly for the new interface
            new_iface->ip = iface->ip;
            new_iface->mask = iface->mask;
            new_iface->helloint = iface->helloint;
            new_iface->neighbor.router_id = iface->neighbor.router_id;
            new_iface->neighbor.neighbor_ip = iface->neighbor.neighbor_ip;
            new_iface->neighbor.last_hello_received = iface->neighbor.last_hello_received;
            new_iface->next_hop = iface->neighbor.neighbor_ip; // Set next hop correctly for the new interface
            new_iface->next = router->interfaces;
            router->interfaces = new_iface;

            printf("[Topology Update] Added new interface to self-router's topology: %s.\n", iface->name);
            return;
        }
        router = router->next;
    }

    printf("[Topology Update] Self-router not found in topology. Cannot update interfaces.\n");
}

/**
 * @brief Checks for neighbor timeouts and updates the topology accordingly.
 *
 * This function iterates over all PWOSPF interfaces in the subsystem to detect
 * neighbors whose HELLO messages have timed out. Any neighbor whose last HELLO
 * reception time exceeds `NEIGHBOR_TIMEOUT` is considered inactive and removed.
 * If a neighbor is removed, the local router's topology is updated and a Link
 * State Update (LSU) flood is triggered, followed by a routing table recalculation.
 *
 * Steps performed:
 * 1. For each interface, check the neighbor's `last_hello_received` timestamp.
 * 2. If the neighbor has timed out, reset the neighbor fields and update the
 *    local router's topology via `update_self_router_topology()`.
 * 3. If any neighbor was removed, print the updated topology, flood an LSU to
 *    notify other routers, recalculate routing, and reset `last_lsu_time`.
 *
 * @param sr             Pointer to the main router instance (`struct sr_instance`).
 * @param last_lsu_time  Pointer to the timestamp tracking when the last LSU was sent.
 *                       This is updated if the topology changes and an LSU is triggered.
 */
void pwospf_check_on_neighbors(struct sr_instance* sr, time_t* last_lsu_time) {
    assert(sr);
    assert(last_lsu_time);

    struct pwospf_interface* iface = sr->ospf_subsys->interfaces;
    time_t now = time(NULL);
    int topology_changed = 0;

    // Iterate through interfaces
    while (iface) {
        struct pwospf_neighbor* neighbor = &iface->neighbor;

        // Check if the neighbor exists and has timed out
        if (neighbor->router_id != 0 && difftime(now, neighbor->last_hello_received) > NEIGHBOR_TIMEOUT) {
            // Convert Router ID to a human-readable IP address using inet_ntop
            char router_id_str[INET_ADDRSTRLEN]; // Buffer for Router ID string
            char neighbor_ip_str[INET_ADDRSTRLEN]; // Buffer for Neighbor IP string

            if (!inet_ntop(AF_INET, &neighbor->router_id, router_id_str, INET_ADDRSTRLEN)) {
                perror("Failed to convert Router ID to string");
                return;
            }

            if (!inet_ntop(AF_INET, &neighbor->neighbor_ip, neighbor_ip_str, INET_ADDRSTRLEN)) {
                perror("Failed to convert Neighbor IP to string");
                return;
            }

            printf("Removing timed-out neighbor: Router ID: %s, IP: %s\n",
                   router_id_str, neighbor_ip_str);

            // Invalidate the neighbor by resetting only the router ID
            neighbor->router_id = 0;
            neighbor->neighbor_ip = 0;
            iface->next_hop = 0; // Reset next hop
            
            update_self_router_topology(sr->ospf_subsys, iface);
            // Mark topology as changed
            topology_changed = 1;
        }

        iface = iface->next;
    }
    
    // Trigger an LSU flood if the topology has changed
    if (topology_changed) {
        printf("Topology has changed.\n");
        print_topology(sr->ospf_subsys);
        printf("Initiating Link State Update due to topology change.\n");
        pwospf_send_lsu(sr, NULL);
        printf("Recalculating routing table.\n");
        recalculate_routing_table(sr);
        // Reset the lsuint counter
        *last_lsu_time = now;
    }
}

/**
 * @brief Constructs and sends a PWOSPF Link State Update (LSU) to active neighbors on all interfaces.
 *
 * This function iterates over every PWOSPF interface in the subsystem (except an
 * optional `exclude_iface`) and sends an LSU packet to each valid neighbor.
 * For each interface:
 * 1. Gathers link information from all interfaces (subnets, masks, and neighbor IDs) 
 *    to form a list of advertisements (LSU entries).
 * 2. Optionally includes a default route advertisement if this router is marked as a gateway.
 * 3. Builds Ethernet, IP, and OSPF headers, then constructs the LSU header (`ospfv2_lsu_hdr`) 
 *    containing the sequence number and TTL.
 * 4. Calculates and sets the OSPF checksum.
 * 5. Sends the packet to the neighbor's IP address using `sr_send_packet()`.
 * 6. Logs each sent packet, indicating the interface, neighbor IP, and number of advertisements.
 *
 * @param sr            Pointer to the main router instance (`struct sr_instance`).
 * @param exclude_iface If non-NULL, the name of an interface to skip sending LSUs on.
 *                     If NULL, all interfaces with a valid neighbor will be used.
 */
void pwospf_send_lsu(struct sr_instance* sr, const char* exclude_iface) {
    struct pwospf_subsys* subsys = sr->ospf_subsys;
    assert(subsys);

    struct pwospf_interface* iface = subsys->interfaces;

    // Iterate through all router interfaces
    while (iface) {
        // Skip the excluded interface
        if (exclude_iface && strcmp(iface->name, exclude_iface) == 0) {
            iface = iface->next;
            continue;
        }

        // Check if the neighbor is valid
        struct pwospf_neighbor* neighbor = &iface->neighbor;
        if (neighbor->router_id == 0) { // Assuming 0 indicates no neighbor
            iface = iface->next;
            continue;
        }

       // Prepare LSU advertisements by collecting link information from all interfaces
        size_t max_adv = 4; // Adjust to account for the possible default route
        struct ospfv2_lsu* adv_array = (struct ospfv2_lsu*)malloc(max_adv * sizeof(struct ospfv2_lsu));
        if (!adv_array) {
            perror("Failed to allocate memory for LSU advertisements");
            return;
        }

        int adv_count = 0; // Count of collected advertisements
        struct pwospf_interface* inner_iface = subsys->interfaces; // Inner loop to collect advertisements
        while (inner_iface && adv_count < max_adv) {
            struct pwospf_neighbor* inner_neighbor = &inner_iface->neighbor;
            if (inner_neighbor->router_id != 0) { // Valid neighbor
                struct ospfv2_lsu* adv = &adv_array[adv_count];
                adv->subnet = inner_iface->ip & inner_iface->mask; // Subnet
                adv->mask = inner_iface->mask; // Mask
                adv->rid = inner_neighbor->router_id; // Neighbor Router ID
                adv_count++;
            } else {
                // No PWOSPF neighbor on this link, advertise RID as 0
                struct ospfv2_lsu* adv = &adv_array[adv_count];
                adv->subnet = inner_iface->ip & inner_iface->mask; // Subnet
                adv->mask = inner_iface->mask; // Mask
                adv->rid = 0; // No neighbor
                adv_count++;
            }
            inner_iface = inner_iface->next;
        }

        // Add default route to advertisements if the router is a gateway
        if (subsys->is_gw && adv_count < max_adv) {
            struct ospfv2_lsu* adv = &adv_array[adv_count++];
            adv->subnet = htonl(0x00000000); // Default subnet
            adv->mask = htonl(0x00000000);   // Default mask
            adv->rid = htonl(0x00000000);    // No PWOSPF neighbor on this link
            printf("Added default route to LSU advertisements.\n");
        }

        // Adjust payload length based on the number of advertisements
        size_t ospf_payload_len = sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + adv_count * sizeof(struct ospfv2_lsu);
        size_t packet_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + ospf_payload_len;

        uint8_t* packet = (uint8_t*)malloc(packet_len);
        if (!packet) {
            perror("Failed to allocate memory for LSU packet");
            free(adv_array);
            return;
        }
        memset(packet, 0, packet_len);

        // Ethernet header
        struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)packet;
        memset(eth_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN); // Broadcast
        struct sr_if* sr_iface = sr_get_interface(sr, iface->name);
        memcpy(eth_hdr->ether_shost, sr_iface->addr, ETHER_ADDR_LEN); // Source MAC
        eth_hdr->ether_type = htons(ETHERTYPE_IP);

        // IP header
        struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
        ip_hdr->ip_v = 4;
        ip_hdr->ip_hl = 5;
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(packet_len - sizeof(struct sr_ethernet_hdr));
        ip_hdr->ip_id = 0;
        ip_hdr->ip_off = 0;
        ip_hdr->ip_ttl = 64;
        ip_hdr->ip_p = 89; // OSPF Protocol
        ip_hdr->ip_src.s_addr = iface->ip;
        ip_hdr->ip_dst.s_addr = neighbor->neighbor_ip;

        // OSPF header
        struct ospfv2_hdr* ospf_hdr = (struct ospfv2_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
        ospf_hdr->version = PWOSPF_VERSION;
        ospf_hdr->type = PWOSPF_TYPE_LSU;
        ospf_hdr->len = htons(ospf_payload_len);
        ospf_hdr->rid = subsys->router_id;
        ospf_hdr->aid = subsys->area_id;
        ospf_hdr->autype = 0;
        ospf_hdr->audata = 0;

        // LSU header
        struct ospfv2_lsu_hdr* lsu_hdr = (struct ospfv2_lsu_hdr*)((uint8_t*)ospf_hdr + sizeof(struct ospfv2_hdr));
        subsys->seq = (subsys->seq + 1) % UINT32_MAX; // Increment sequence number
        lsu_hdr->seq = subsys->seq;
        lsu_hdr->ttl = 64; // Default TTL
        lsu_hdr->num_adv = htonl(adv_count); // Number of advertisements

        // Copy advertisements into the packet
        struct ospfv2_lsu* adv_packet = (struct ospfv2_lsu*)((uint8_t*)lsu_hdr + sizeof(struct ospfv2_lsu_hdr));
        memcpy(adv_packet, adv_array, adv_count * sizeof(struct ospfv2_lsu));

        // Calculate checksum
        ospf_hdr->csum = 0; // Clear checksum field

        // Allocate aligned buffer for LSU checksum calculation
        size_t ospf_len = ospf_payload_len; // Length of the OSPF payload
        size_t aligned_len = ospf_len + (ospf_len % 2); // Ensure even length
        uint8_t* aligned_buf = (uint8_t*)malloc(aligned_len);
        if (!aligned_buf) {
            perror("Failed to allocate memory for checksum buffer");
            free(packet);
            free(adv_array);
            return;
        }

        // Copy the OSPF payload into the aligned buffer
        memcpy(aligned_buf, ospf_hdr, ospf_len);

        // Pad with zero if the payload length is odd
        if (ospf_len % 2 != 0) {
            aligned_buf[ospf_len] = 0;
        }

        // Calculate the checksum
        ospf_hdr->csum = checksum_pwospf((uint16_t*)aligned_buf, aligned_len / 2);

        free(aligned_buf); // Free the allocated buffer

        // Send packet
        sr_send_packet(sr, packet, packet_len, iface->name);
        printf("Sent LSU from interface: %s to neighbor IP: %s with %d advertisements\n",
               iface->name, inet_ntoa(*(struct in_addr*)&neighbor->neighbor_ip), adv_count);

        // Cleanup
        free(packet);
        free(adv_array);

        iface = iface->next;
    }
}
/**
 * @brief Updates the sequence number and last updated timestamp for a router entry.
 *
 * This function is called when an LSU packet has no topology changes,
 * but the sequence number of the packet is higher than the stored one,
 * requiring the sequence number and timestamp to be updated.
 *
 * @param router_entry Pointer to the router entry in the topology database.
 * @param seq The new sequence number to update.
 */
void pwospf_update_router_sequence_number(struct pwospf_router* router_entry, uint32_t seq) {
    if (!router_entry) {
        printf("[Error] Null router entry passed to pwospf_update_router_sequence_number.\n");
        return;
    }

    // Update the sequence number
    router_entry->last_sequence = seq;

    // Update the last updated timestamp
    router_entry->last_updated = time(NULL);
    char router_id_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &router_entry->router_id, router_id_str, INET_ADDRSTRLEN)) {
        perror("Failed to convert Router ID to string");
        return;
    }
    printf("[Router Update] Updated Router ID: %s with Sequence: %u, Timestamp: %ld\n",
           router_id_str, seq, router_entry->last_updated);
}
/**
 * @brief Validates the LSU packet.
 *
 * @param sr Pointer to the router instance.
 * @param subsys Pointer to the PWOSPF subsystem.
 * @param ospf_hdr Pointer to the OSPF header.
 * @param seq Sequence number of the LSU packet.
 * @param interface Incoming interface for the packet.
 * @return int 1 if the packet is valid, 0 otherwise.
 */
int pwospf_validate_lsu_packet(struct sr_instance* sr, struct pwospf_subsys* subsys,
                                struct ospfv2_hdr* ospf_hdr, uint32_t seq, char* interface) {
    if (ospf_hdr->rid == subsys->router_id) {
        printf("Discarded LSU packet: self-originated.\n");
        return 0;
    }

    struct pwospf_router* router_entry = pwospf_find_router_entry(subsys, ospf_hdr->rid);
    if (router_entry && seq <= router_entry->last_sequence) {
        printf("Discarded LSU packet: stale or redundant sequence number.\n");
        return 0;
    }

    return 1;
}

/**
 * @brief Finds a router entry in the topology database.
 *
 * @param subsys Pointer to the PWOSPF subsystem.
 * @param router_id Router ID to search for.
 * @return Pointer to the router entry if found, NULL otherwise.
 */
struct pwospf_router* pwospf_find_router_entry(struct pwospf_subsys* subsys, uint32_t router_id) {
    struct pwospf_router* entry = subsys->topology;
    while (entry) {
        if (entry->router_id == router_id) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

/**
 * @brief Updates an existing router's topology in the database.
 *
 * @param router_entry Pointer to the router entry.
 * @param lsu_adv Pointer to the LSU advertisements.
 * @param num_links Number of links in the LSU.
 * @param seq Sequence number of the LSU.
 */
void pwospf_update_router_topology(struct pwospf_router* router_entry,
                                   struct ospfv2_lsu* lsu_adv, uint32_t num_links, uint32_t seq) {
    char router_id_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &router_entry->router_id, router_id_str, INET_ADDRSTRLEN)) {
        perror("Failed to convert Router ID to string");
        return;
    }
    printf("[Topology Update] Updating topology for Router ID: %s\n", router_id_str);

    // Free old interface list
    struct pwospf_interface* iface = router_entry->interfaces;
    while (iface) {
        struct pwospf_interface* next = iface->next;
        free(iface);
        iface = next;
    }

    // Add new interfaces from the LSU
    router_entry->interfaces = NULL;
    for (uint32_t i = 0; i < num_links; i++) {
        struct pwospf_interface* new_iface = malloc(sizeof(struct pwospf_interface));
        if (!new_iface) {
            perror("Failed to allocate memory for interface");
            return;
        }
        memset(new_iface, 0, sizeof(struct pwospf_interface));

        // Populate interface fields based on LSU advertisement
        new_iface->ip = lsu_adv[i].subnet;                     // Subnet
        new_iface->mask = lsu_adv[i].mask;                     // Subnet mask
        new_iface->neighbor.router_id = lsu_adv[i].rid;        // Neighbor router ID
        new_iface->neighbor.neighbor_ip = 0;                   // Cannot determine from LSU
        new_iface->helloint = 10;                              // Default HELLO interval (assumption)

        // Add the new interface to the linked list
        new_iface->next = router_entry->interfaces;
        router_entry->interfaces = new_iface;
    }

    router_entry->last_sequence = seq;
    router_entry->last_updated = time(NULL); // Timestamp for when this router's topology was last updated

    printf("[Topology Update] Updated topology for Router ID: %s\n", router_id_str);
}
/**
 * @brief Determines if the received LSU indicates a change in the topology.
 *
 * @param router_entry Pointer to the existing router entry in the topology.
 * @param lsu_adv Pointer to the LSU advertisements.
 * @param num_links Number of links in the LSU advertisement.
 * @return int 1 if the topology has changed, 0 otherwise.
 */
int topology_changed(struct pwospf_router* router_entry, struct ospfv2_lsu* lsu_adv, uint32_t num_links) {
    struct pwospf_interface* iface = router_entry->interfaces;

    // Track visited links from the LSU to detect removal of existing links
    int* visited_links = calloc(num_links, sizeof(int));
    if (!visited_links) {
        perror("Failed to allocate memory for tracking visited links");
        return 1; // Assume change to avoid ignoring updates
    }

    // Step 1: Check for changes in existing links
    struct pwospf_interface* current_iface = iface;
    while (current_iface) {
        int link_found = 0;

        for (uint32_t i = 0; i < num_links; i++) {
            if ((current_iface->ip == lsu_adv[i].subnet) &&
                (current_iface->mask == lsu_adv[i].mask)) {
                
                link_found = 1; // Match found

                // Check for state changes
                char subnet_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &lsu_adv[i].subnet, subnet_str, INET_ADDRSTRLEN);
                if (current_iface->neighbor.router_id != lsu_adv[i].rid) {
                    if (lsu_adv[i].rid == 0) {
                        printf("[Topology Change] Link down detected for subnet %s\n", subnet_str);
                    } else if (current_iface->neighbor.router_id == 0) {
                        printf("[Topology Change] Link up detected for subnet %s\n", subnet_str);
                    } else { 
                        printf("[Topology Change] Neighbor ID changed for subnet %s\n", subnet_str);
                    }
                    free(visited_links);
                    return 1;
                }

                visited_links[i] = 1; // Mark this link as visited
                break;
            }
        }

        if (!link_found) {
            // Current link in topology is missing in the LSU
            printf("[Topology Change] Link removed: Subnet=%u\n", current_iface->ip);
            free(visited_links);
            return 1;
        }

        current_iface = current_iface->next;
    }

    // Step 2: Check for addition of new links
    for (uint32_t i = 0; i < num_links; i++) {
        if (!visited_links[i]) {
            printf("[Topology Change] New link detected: Subnet=%u\n", lsu_adv[i].subnet);
            free(visited_links);
            return 1;
        }
    }

    free(visited_links);

    // Step 3: No changes detected
    return 0;
}

/**
 * @brief Adds a new router entry to the topology database.
 *
 * @param subsys Pointer to the PWOSPF subsystem.
 * @param router_id Router ID of the new router.
 * @param lsu_adv Pointer to the LSU advertisements.
 * @param num_links Number of links in the LSU.
 * @param seq Sequence number of the LSU.
 */
void pwospf_add_new_router_to_topology(struct pwospf_subsys* subsys, uint32_t router_id,
                                       struct ospfv2_lsu* lsu_adv, uint32_t num_links, uint32_t seq) {
    char router_id_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &router_id, router_id_str, INET_ADDRSTRLEN)) {
        perror("Failed to convert Router ID to string");
        return;
    }
    printf("[Topology Update] Adding new router to topology: Router ID: %s\n", router_id_str);

    struct pwospf_router* new_router = malloc(sizeof(struct pwospf_router));
    if (!new_router) {
        perror("Failed to allocate memory for new router");
        return;
    }
    memset(new_router, 0, sizeof(struct pwospf_router));

    new_router->router_id = router_id;
    new_router->area_id = subsys->area_id;
    new_router->last_sequence = seq;
    new_router->last_updated = time(NULL);

    for (uint32_t i = 0; i < num_links; i++) {
        struct pwospf_interface* new_iface = malloc(sizeof(struct pwospf_interface));
        if (!new_iface) {
            perror("Failed to allocate memory for interface");
            free(new_router);
            return;
        }
        memset(new_iface, 0, sizeof(struct pwospf_interface));
        new_iface->ip = lsu_adv[i].subnet;
        new_iface->mask = lsu_adv[i].mask;
        new_iface->neighbor.router_id = lsu_adv[i].rid;
        new_iface->next = new_router->interfaces;
        new_router->interfaces = new_iface;
    }

    new_router->next = subsys->topology;
    subsys->topology = new_router;

    printf("[Topology Update] Added new router to topology: Router ID: %s\n", router_id_str);
}
/**
 * @brief Floods an LSU packet to all neighbors except the specified interface.
 *
 * This function decrements the TTL, recalculates the checksum, and sends
 * the LSU packet to all neighbors except the incoming interface.
 *
 * @param sr Pointer to the router instance.
 * @param packet Pointer to the LSU packet to be flooded.
 * @param len Length of the LSU packet.
 * @param interface The interface through which the packet was received (excluded from flooding).
 */
void pwospf_flood_lsu(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {

    // Decrement TTL
    struct ospfv2_lsu_hdr* lsu_hdr = (struct ospfv2_lsu_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
    lsu_hdr->ttl--;

    if (lsu_hdr->ttl <= 0) {
        printf("[LSU Flooding] TTL expired. Dropping packet.\n");
        return; // Drop the packet if TTL is zero or less
    }

    // Recalculate OSPF checksum
    struct ospfv2_hdr* ospf_hdr = (struct ospfv2_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    ospf_hdr->csum = 0; // Clear the checksum field before recalculation

    size_t ospf_payload_len = len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip);
    uint16_t* ospf_payload = malloc(ospf_payload_len);
    if (!ospf_payload) {
        perror("[LSU Flooding] Failed to allocate memory for checksum calculation.");
        return;
    }
    memcpy(ospf_payload, ospf_hdr, ospf_payload_len);

    ospf_hdr->csum = checksum_pwospf(ospf_payload, ospf_payload_len / 2);
    free(ospf_payload);

    // Flood to all neighbors except the incoming interface
    struct pwospf_interface* iface = sr->ospf_subsys->interfaces;
    while (iface) {
        if (strcmp(iface->name, interface) != 0) {
            // modify the source mac address
            struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)packet;
            struct sr_if* sr_iface = sr_get_interface(sr, iface->name);
            memcpy(eth_hdr->ether_shost, sr_iface->addr, ETHER_ADDR_LEN); // Source MAC

            printf("[LSU Flooding] Forwarding LSU packet via interface: %s\n", iface->name);
            sr_send_packet(sr, packet, len, iface->name);
        }
        iface = iface->next;
    }
}

/**
 * @brief Checks if a link between two routers is valid by verifying bidirectional neighbor relationships.
 *
 * This function examines the specified interface (`iface1`) on `router1` and looks
 * for an interface on `router2` such that each router identifies the other as its neighbor.
 *
 * @param router1 Pointer to the first router in the link.
 * @param iface1  Pointer to the interface on `router1` that should have `router2` as a neighbor.
 * @param router2 Pointer to the second router in the link.
 * @return `true` if both sides list each other as a neighbor, `false` otherwise.
 */
bool is_valid_link(struct pwospf_router* router1, struct pwospf_interface* iface1,
                  struct pwospf_router* router2) {
    // Check if router2 lists router1 as a neighbor
    for (struct pwospf_interface* iface2 = router2->interfaces; iface2; iface2 = iface2->next) {
        if (iface2->neighbor.router_id == router1->router_id && 
            iface1->neighbor.router_id == router2->router_id) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Perform BFS to compute shortest paths to all subnets.
 *
 * @param topology Pointer to the topology database.
 * @param source_router_id The router ID of the current router.
 * @return A struct containing the shortest path results.
 */
struct shortest_path_result* bfs_shortest_paths(struct pwospf_router* topology, uint32_t source_router_id) {
    // Allocate memory for the result
    struct shortest_path_result* result = malloc(sizeof(struct shortest_path_result));
    if (!result) {
        perror("[Error] Failed to allocate memory for shortest path result");
        return NULL;
    }
    memset(result, 0, sizeof(struct shortest_path_result));

    // Dynamic queue for BFS with path tracking
    struct {
        int distance;
        struct pwospf_router* router;
        struct pwospf_interface* first_hop_iface;  // Interface to use for this path
        uint32_t next_hop_ip;  // Next hop IP for this path
    } *queue;

    queue = malloc(sizeof(*queue) * MAX_ROUTERS);
    if (!queue) {
        free(result);
        perror("[Error] Failed to allocate memory for BFS queue");
        return NULL;
    }

    // Tracking structures
    bool visited[MAX_ROUTERS] = {false};
    uint32_t router_ids[MAX_ROUTERS] = {0};
    uint32_t router_count = 0;

    // Helper function to get or add router index
    int get_router_index(uint32_t router_id) {
        for (uint32_t i = 0; i < router_count; i++) {
            if (router_ids[i] == router_id) {
                return i;
            }
        }
        if (router_count < MAX_ROUTERS) {
            router_ids[router_count] = router_id;
            return router_count++;
        }
        return -1;
    }

    // Find source router
    struct pwospf_router* source_router = NULL;
    for (struct pwospf_router* r = topology; r; r = r->next) {
        if (r->router_id == source_router_id) {
            source_router = r;
            break;
        }
    }

    if (!source_router) {
        free(queue);
        free(result);
        return NULL;
    }

    // Initialize BFS
    int front = 0, rear = 0;
    int source_index = get_router_index(source_router_id);
    queue[rear].router = source_router;
    queue[rear].distance = 0;
    queue[rear].first_hop_iface = NULL;  // No hop for source
    queue[rear].next_hop_ip = 0;  // No next hop for source
    rear++;

    visited[source_index] = true;

    // BFS Processing
    while (front < rear) {
        struct pwospf_router* current_router = queue[front].router;
        int current_distance = queue[front].distance;
        struct pwospf_interface* current_first_hop = queue[front].first_hop_iface;
        uint32_t current_next_hop = queue[front].next_hop_ip;
        front++;

        // Process all interfaces of current router
        for (struct pwospf_interface* iface = current_router->interfaces; iface; iface = iface->next) {
            // Skip interfaces without valid neighbor
            uint32_t neighbor_id = iface->neighbor.router_id;
            if (neighbor_id == 0) continue;

            int neighbor_index = get_router_index(neighbor_id);

            // Find neighbor router
            struct pwospf_router* neighbor_router = NULL;
            for (struct pwospf_router* r = topology; r; r = r->next) {
                if (r->router_id == neighbor_id) {
                    neighbor_router = r;
                    break;
                }
            }

            if (!neighbor_router) continue;

            // Verify bidirectional link
            if (!is_valid_link(current_router, iface, neighbor_router)) continue;

            if (!visited[neighbor_index]) {
                visited[neighbor_index] = true;
                queue[rear].router = neighbor_router;
                queue[rear].distance = current_distance + 1;

                // If this is a direct neighbor of source
                if (current_distance == 0) {
                    queue[rear].first_hop_iface = iface;
                    queue[rear].next_hop_ip = iface->neighbor.neighbor_ip;
                } else {
                    // Preserve the original first hop
                    queue[rear].first_hop_iface = current_first_hop;
                    queue[rear].next_hop_ip = current_next_hop;
                }
                rear++;

                // Add subnets from neighbor router
                for (struct pwospf_interface* neighbor_iface = neighbor_router->interfaces; 
                    neighbor_iface; neighbor_iface = neighbor_iface->next) {
                    struct shortest_path_entry* new_entry = malloc(sizeof(struct shortest_path_entry));
                    if (!new_entry) {
                        perror("[Error] Failed to allocate memory for shortest path entry");
                        continue;
                    }

                    // Regular subnet entry
                    new_entry->subnet = neighbor_iface->ip & neighbor_iface->mask;
                    new_entry->mask = neighbor_iface->mask;
                    new_entry->next_hop = queue[rear-1].next_hop_ip;
                    
                    if (queue[rear-1].first_hop_iface) {
                        strncpy(new_entry->interface, queue[rear-1].first_hop_iface->name, 
                            sizeof(new_entry->interface) - 1);
                        new_entry->interface[sizeof(new_entry->interface) - 1] = '\0';
                    } else {
                        new_entry->interface[0] = '\0';
                    }

                    // Prepend to list
                    new_entry->next = result->entries;
                    result->entries = new_entry;

                    // If this neighbor has a default route (0.0.0.0/0), add a default route entry
                    if (neighbor_iface->ip == 0 && neighbor_iface->mask == 0) {
                        struct shortest_path_entry* default_entry = malloc(sizeof(struct shortest_path_entry));
                        if (!default_entry) {
                            perror("[Error] Failed to allocate memory for default route entry");
                            continue;
                        }

                        default_entry->subnet = 0;  // 0.0.0.0
                        default_entry->mask = 0;    // 0.0.0.0
                        default_entry->next_hop = queue[rear-1].next_hop_ip;
                        
                        if (queue[rear-1].first_hop_iface) {
                            strncpy(default_entry->interface, queue[rear-1].first_hop_iface->name, 
                                sizeof(default_entry->interface) - 1);
                            default_entry->interface[sizeof(default_entry->interface) - 1] = '\0';
                        } else {
                            default_entry->interface[0] = '\0';
                        }

                        default_entry->next = result->entries;
                        result->entries = default_entry;
                    }
                }
            }
        }
    }

    free(queue);
    return result;
}
/**
 * @brief Frees the memory allocated for a shortest path result and its entries.
 *
 * This function de-allocates the linked list of `shortest_path_entry` structures
 * in the `entries` field, then frees the `shortest_path_result` object itself.
 *
 * @param result Pointer to the `shortest_path_result` structure to be freed.
 *               If `result` is NULL, the function returns immediately.
 */
void free_shortest_path_result(struct shortest_path_result* result) {
    if (!result) {
        return;
    }

    struct shortest_path_entry* entry = result->entries;
    while (entry) {
        struct shortest_path_entry* next = entry->next;
        free(entry);
        entry = next;
    }
    free(result);
}
/**
 * @brief Handles incoming LSU packets for the PWOSPF protocol.
 *
 * @param sr Pointer to the router instance.
 * @param packet Pointer to the received packet.
 * @param len Length of the received packet.
 * @param interface Incoming interface for the packet.
 */
void pwospf_handle_lsu(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
    struct ospfv2_hdr* ospf_hdr = (struct ospfv2_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + (ip_hdr->ip_hl * 4));
    struct ospfv2_lsu_hdr* lsu_hdr = (struct ospfv2_lsu_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + (ip_hdr->ip_hl * 4) + sizeof(struct ospfv2_hdr));
    struct ospfv2_lsu* lsu_adv = (struct ospfv2_lsu*)((uint8_t*)lsu_hdr + sizeof(struct ospfv2_lsu_hdr));

    uint32_t num_links = ntohl(lsu_hdr->num_adv);
    uint32_t seq = lsu_hdr->seq;

    printf("Received LSU from Router ID: %s, Seq: %u, Links: %u\n",
           inet_ntoa(*(struct in_addr*)&ospf_hdr->rid), seq, num_links);

    struct pwospf_subsys* subsys = sr->ospf_subsys;

    // Step 1: Validate LSU
    if (!pwospf_validate_lsu_packet(sr, subsys, ospf_hdr, seq, interface)) {
        return; // Discard invalid or redundant packets
    }
     // print lsu advertisements
    print_lsu_debug_info(ospf_hdr->rid, ip_hdr->ip_src.s_addr, num_links, lsu_adv);

    // Step 2: Check for topology changes
    struct pwospf_router* router_entry = pwospf_find_router_entry(subsys, ospf_hdr->rid);
    if (router_entry) {
        if (!topology_changed(router_entry, lsu_adv, num_links)) {
            printf("[LSU] No topology changes detected. Updating sequence number.\n");
            pwospf_update_router_sequence_number(router_entry, seq);
            return;
        }
    }
   
    // Step 3: Update topology graph
    if (router_entry) {
        pwospf_update_router_topology(router_entry, lsu_adv, num_links, seq);
    } else {
        pwospf_add_new_router_to_topology(subsys, ospf_hdr->rid, lsu_adv, num_links, seq);
    }

    // print router topology
    print_topology(subsys);

    // Step 4: Recalculate routing table
    recalculate_routing_table(sr);

    // Step 5: Flood LSU to other neighbors
    printf("[LSU] Flooding LSU to other neighbor except %s.\n", interface);
    pwospf_flood_lsu(sr, packet, len, interface);
}

/**
 * @brief Prints the list of computed shortest path entries in human-readable format.
 *
 * This function iterates over the linked list of `shortest_path_entry` objects
 * within the given `shortest_path_result`. For each entry, it converts the
 * subnet, mask, and next hop from numeric to string form, and then prints the
 * resulting route details alongside the corresponding interface.
 *
 * @param result Pointer to the `shortest_path_result` containing the entries
 *               to be printed. If `result` or its `entries` field is NULL,
 *               the function reports that no paths were computed.
 */
void print_shortest_paths(struct shortest_path_result* result) {
    if (!result || !result->entries) {
        printf("No shortest paths computed or the result is empty.\n");
        return;
    }

    printf("=========== Shortest Path Results ===========\n");
    struct shortest_path_entry* entry = result->entries;
    while (entry) {
        char subnet_str[INET_ADDRSTRLEN], mask_str[INET_ADDRSTRLEN], next_hop_str[INET_ADDRSTRLEN];

        // Convert numeric fields to human-readable strings
        inet_ntop(AF_INET, &entry->subnet, subnet_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &entry->mask, mask_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &entry->next_hop, next_hop_str, INET_ADDRSTRLEN);

        // Print the entry
        printf("Subnet: %-15s Mask: %-15s Next Hop: %-15s Interface: %s\n",
               subnet_str, mask_str, next_hop_str, entry->interface);

        entry = entry->next;
    }
    printf("=============================================\n");
}

/**
 * @brief Removes all non-directly connected routes from the routing table,
 *        preserving directly connected routes and the default route
 * 
 * @param sr Pointer to the router instance
 */
void clear_non_direct_routes(struct sr_instance* sr) {
    struct sr_rt* rt = sr->routing_table;
    struct sr_rt* prev = NULL;
    
    while (rt) {
        struct sr_rt* next = rt->next;
        // Keep the route if it's directly connected (gw.s_addr == 0) 
        // OR if it's the default route (dest.s_addr == 0)
        if (rt->gw.s_addr != 0 && rt->dest.s_addr != 0) {
            if (prev) {
                prev->next = next;
            } else {
                sr->routing_table = next;
            }
            free(rt);
        } else {
            prev = rt;
        }
        rt = next;
    }
}

/**
 * @brief Recalculates the routing table based on the current topology graph.
 *
 * This function computes the shortest paths to all subnets in the topology and updates
 * the routing table with next-hop and interface information.
 *
 * @param sr Pointer to the router instance.
 */
void recalculate_routing_table(struct sr_instance* sr) {
    if (!sr || !sr->ospf_subsys) {
        printf("[Error] Invalid router instance or OSPF subsystem.\n");
        return;
    }

    struct pwospf_subsys* subsys = sr->ospf_subsys;
    struct pwospf_router* topology = subsys->topology;
    uint32_t source_router_id = subsys->router_id;

    // Clear existing non-direct routes before recalculating
    clear_non_direct_routes(sr);

    printf("Running BFS on updated topology to compute new shortest...\n");

    struct shortest_path_result* shortest_paths = bfs_shortest_paths(topology, source_router_id);
    if (!shortest_paths) {
        printf("[Error] BFS failed. Cannot update routing table.\n");
        return;
    }
    printf("[Debug] BFS completed successfully.\n");
    printf("[Debug] New shortest paths:\n");
    print_shortest_paths(shortest_paths);

    // Buffers for IP address strings
    char subnet_str[INET_ADDRSTRLEN];
    char mask_str[INET_ADDRSTRLEN];
    char next_hop_str[INET_ADDRSTRLEN];

    // Process each shortest path entry
    struct shortest_path_entry* entry = shortest_paths->entries;
    while (entry) {
        if (!entry) {
            printf("[Error] NULL entry in shortest path results.\n");
            break;
        }

        // Convert IP addresses to strings
        const char* subnet_result = inet_ntop(AF_INET, &entry->subnet, subnet_str, INET_ADDRSTRLEN);
        const char* mask_result = inet_ntop(AF_INET, &entry->mask, mask_str, INET_ADDRSTRLEN);
        const char* next_hop_result = inet_ntop(AF_INET, &entry->next_hop, next_hop_str, INET_ADDRSTRLEN);

        if (!subnet_result || !mask_result || !next_hop_result) {
            perror("[Routing Table] inet_ntop failed for one or more fields");
            entry = entry->next;
            continue;
        }

        // Check if route exists
        struct sr_rt* existing_entry = lookup_route_by_subnet(sr, entry->subnet);
        if (existing_entry) {
            // Always update default routes when topology changes
            if (entry->subnet == 0 && entry->mask == 0) {
                update_rtable_entry(sr, existing_entry, entry->next_hop, entry->mask, entry->interface);
            }
            // For non-default routes, only update if directly connected
            else if (existing_entry->gw.s_addr == 0) {
                update_rtable_entry(sr, existing_entry, entry->next_hop, entry->mask, entry->interface);
            }
        }
        else {
            // Add new route
            create_rtable_entry(sr, entry->subnet, entry->next_hop, entry->mask, entry->interface);
        }

        entry = entry->next;
    }

    free_shortest_path_result(shortest_paths);
    sr_print_routing_table(sr);
}
/**
 * @brief Calculates the PWOSPF checksum over a buffer of 16-bit words.
 *
 * This function sums the 16-bit words in the provided buffer (converting each
 * from network byte order to host byte order via `ntohs`), applying carry handling
 * to wrap around overflow bits. It returns the final one’s complement of the
 * accumulated sum.
 *
 * @param buf   Pointer to the buffer of 16-bit words to be checksummed.
 * @param count Number of 16-bit words in the buffer.
 * @return The 16-bit PWOSPF checksum (in host byte order).
 */
uint16_t checksum_pwospf(uint16_t* buf, size_t count) {
    uint32_t sum = 0;

    for (size_t i = 0; i < count; i++) {
        sum += ntohs(buf[i]);  // Convert network-byte-order to host-byte-order
        if (sum > 0xFFFF) {    // Handle carry
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }

    return ~((sum & 0xFFFF));  // Finalize checksum
}

/**
 * @brief Scans the router’s static routing table and updates the PWOSPF subsystem based on default routes.
 *
 * This function iterates through every entry in the router's `sr->routing_table` and prints
 * each static route’s details: destination, gateway, mask, and interface. If any entry
 * represents a default route (destination == 0), it checks for a matching PWOSPF interface
 * with the same name and:
 *
 * - Sets that interface's neighbor IP to the gateway address.
 * - Marks the subsystem as a gateway router (`subsys->is_gw = true`).
 *
 * @param sr     Pointer to the main router instance. Must have a valid `routing_table`.
 * @param subsys Pointer to the PWOSPF subsystem. Updated if a default route is found.
 */
void read_static_routes(struct sr_instance* sr, struct pwospf_subsys* subsys) {
    if (!sr->routing_table) {
        printf("Routing table is empty.\n");
        return;
    }

    printf("Reading static routes from the routing table:\n");
    struct sr_rt* rt_walker = sr->routing_table;

    while (rt_walker) {
        struct in_addr dest = rt_walker->dest;
        struct in_addr gw = rt_walker->gw;
        struct in_addr mask = rt_walker->mask;
        const char* iface = rt_walker->interface;

        printf("Static route found:\n");
        printf("  Destination: %s\n", inet_ntoa(dest));
        printf("  Gateway: %s\n", inet_ntoa(gw));
        printf("  Mask: %s\n", inet_ntoa(mask));
        printf("  Interface: %s\n", iface);

        if (dest.s_addr == 0) {
            struct pwospf_interface* pwospf_iface = subsys->interfaces;
            while (pwospf_iface) {
                if (strcmp(pwospf_iface->name, iface) == 0) {
                    pwospf_iface->neighbor.router_id = 0;
                    pwospf_iface->neighbor.neighbor_ip = gw.s_addr;

                    subsys->is_gw = true; // Mark as gateway
                    printf("This router is a gateway router.\n");
                    break;
                }
                pwospf_iface = pwospf_iface->next;
            }
        }

        rt_walker = rt_walker->next;
    }
}

/**
 * @brief Prints the current PWOSPF topology in a tabular format for each router in the subsystem.
 *
 * This function iterates over each router in `subsys->topology` and prints:
 * - A header identifying the router by its Router ID.
 * - A table listing each interface's subnet (IP & mask), Neighbor Router ID, and next hop.
 * 
 * Steps performed:
 * 1. Convert each router's ID into a string and create a centered header.
 * 2. For each interface in the router, compute the subnet by bitwise-AND of IP and mask.
 * 3. Convert the subnet, mask, neighbor router ID, and next hop into human-readable strings.
 * 4. Print the resulting table rows in a formatted manner.
 *
 * @param subsys Pointer to the PWOSPF subsystem containing the `topology` linked list.
 */
void print_topology(struct pwospf_subsys* subsys) {
    struct pwospf_router* router = subsys->topology;
    printf("=================================================================================\n");
    printf("Current Topology:\n");
    printf("=================================================================================\n");

    char router_id_str[INET_ADDRSTRLEN];
    char subnet_str[INET_ADDRSTRLEN];
    char mask_str[INET_ADDRSTRLEN];
    char neighbor_id_str[INET_ADDRSTRLEN];
    char next_hop_str[INET_ADDRSTRLEN];

    const int table_width = 66; // Total table width (without borders)
    const int border_width = 4; // The table's vertical line border padding (`+---+`)

    while (router) {
        if (!inet_ntop(AF_INET, &router->router_id, router_id_str, INET_ADDRSTRLEN)) {
            perror("Failed to convert Router ID to string");
            router = router->next;
            continue;
        }

        // Build the Router ID header
        char header[128];
        snprintf(header, sizeof(header), " Router ID: %s ", router_id_str);
        int header_len = strlen(header);

        // Calculate the padding needed to center the header
        int total_width = table_width + border_width * 4; // Account for full table width
        int padding = (total_width - header_len) / 2;

        printf("%.*s%s%.*s\n", padding, "************************************************",
               header, padding, "************************************************");

        printf("+------------------+------------------+------------------+------------------+\n");
        printf("|      Subnet      |       Mask       |   Neighbor ID    |     Next Hop     |\n");
        printf("+------------------+------------------+------------------+------------------+\n");

        struct pwospf_interface* iface = router->interfaces;
        while (iface) {
            uint32_t subnet = iface->ip & iface->mask;
            if (!inet_ntop(AF_INET, &subnet, subnet_str, INET_ADDRSTRLEN)) {
                perror("Failed to convert Subnet to string");
                iface = iface->next;
                continue;
            }
            if (!inet_ntop(AF_INET, &iface->mask, mask_str, INET_ADDRSTRLEN)) {
                perror("Failed to convert Mask to string");
                iface = iface->next;
                continue;
            }
            if (!inet_ntop(AF_INET, &iface->neighbor.router_id, neighbor_id_str, INET_ADDRSTRLEN)) {
                perror("Failed to convert Neighbor Router ID to string");
                iface = iface->next;
                continue;
            }
            if (!inet_ntop(AF_INET, &iface->next_hop, next_hop_str, INET_ADDRSTRLEN)) {
                perror("Failed to convert Next Hop to string");
                iface = iface->next;
                continue;
            }

            printf("| %-16s | %-16s | %-16s | %-16s |\n",
                   subnet_str, mask_str, neighbor_id_str, next_hop_str);
            iface = iface->next;
        }
        printf("+------------------+------------------+------------------+------------------+\n\n");
        router = router->next;
    }
    printf("=================================================================================\n");
}

/**
 * @brief Prints debug information for an LSU packet.
 *
 * This function prints the Router ID and Neighbor IP of the LSU packet, followed by
 * a list of the advertised links (subnets, masks, and neighbor IDs).
 *
 * @param router_id    Router ID of the OSPF header.
 * @param neighbor_ip  Neighbor IP address of the LSU packet.
 * @param num_links    Number of advertised links in the LSU packet.
 * @param lsu_adv      Pointer to the first advertised link in the LSU packet.
 */
void print_lsu_debug_info(uint32_t router_id, uint32_t neighbor_ip, uint32_t num_links, struct ospfv2_lsu* lsu_adv) {
    char router_id_str[INET_ADDRSTRLEN];
    char neighbor_ip_str[INET_ADDRSTRLEN];

    if (!inet_ntop(AF_INET, &router_id, router_id_str, INET_ADDRSTRLEN)) {
        perror("Failed to convert Router ID to string");
        return;
    }
    if (!inet_ntop(AF_INET, &neighbor_ip, neighbor_ip_str, INET_ADDRSTRLEN)) {
        perror("Failed to convert Neighbor IP to string");
        return;
    }

    printf("LSU from Router ID: %s, Neighbor IP: %s\n", router_id_str, neighbor_ip_str);
    for (uint32_t i = 0; i < num_links; i++) {
        uint32_t subnet = lsu_adv[i].subnet;
        uint32_t mask = lsu_adv[i].mask;
        uint32_t rid = lsu_adv[i].rid;
        char subnet_str[INET_ADDRSTRLEN];
        char mask_str[INET_ADDRSTRLEN];
        char rid_str[INET_ADDRSTRLEN];
        printf("Link %d: Subnet: %s, Mask: %s, Neighbor ID: %s\n", i,
               inet_ntop(AF_INET, &subnet, subnet_str, INET_ADDRSTRLEN),
               inet_ntop(AF_INET, &mask, mask_str, INET_ADDRSTRLEN),
               inet_ntop(AF_INET, &rid, rid_str, INET_ADDRSTRLEN));
    }
}

/**
 * Function: node_exists
 * ----------------------
 * Checks if a node with the given router ID and subnet exists in the global topology graph.
 * 
 * @param router_id: The router ID to search for.
 * @param subnet: The subnet to search for.
 * @return: Pointer to the node if it exists, NULL otherwise.
 */
struct node* node_exists(uint32_t router_id, uint32_t subnet) {
    // Start at the global node list (graph head)
    struct node* current = nodes;

    // Traverse the list to find a matching node
    while (current) {
        printf("[Node Exists] Checking node: Router ID=%u, Subnet=%u\n", current->router_id, current->subnet);
        if (current->router_id == router_id && current->subnet == subnet) {
            printf("[Node Exists] Match found: Router ID=%u, Subnet=%u\n", router_id, subnet);
            return current; // Match found
        }
        current = current->next; // Move to the next node in the list
    }

    printf("[Node Exists] No match found for Router ID=%u, Subnet=%u\n", router_id, subnet);
    return NULL; // No match found
}

/**
 * @brief Creates and adds a new entry to the routing table.
 *
 * This function adds a route to the routing table using the provided destination,
 * next hop, mask, and interface. It utilizes `sr_add_rt_entry` to perform the actual
 * addition. Debug information is printed for verification.
 *
 * @param sr Pointer to the router instance.
 * @param dest Destination subnet (network byte order).
 * @param next_hop Next hop IP address (network byte order).
 * @param mask Subnet mask (network byte order).
 * @param iface Name of the interface associated with this route.
 */
void create_rtable_entry(struct sr_instance *sr, uint32_t dest, uint32_t next_hop, uint32_t mask, char *iface) {
    // printf("\n[Routing Table] Creating Entry...\n");

    // Buffers for IP address strings
    char dest_str[INET_ADDRSTRLEN], next_hop_str[INET_ADDRSTRLEN], mask_str[INET_ADDRSTRLEN];

    // Convert addresses to strings
    if (!inet_ntop(AF_INET, &dest, dest_str, INET_ADDRSTRLEN)) {
        perror("inet_ntop failed for destination");
        strncpy(dest_str, "INVALID", INET_ADDRSTRLEN);
    }
    if (!inet_ntop(AF_INET, &next_hop, next_hop_str, INET_ADDRSTRLEN)) {
        perror("inet_ntop failed for next hop");
        strncpy(next_hop_str, "INVALID", INET_ADDRSTRLEN);
    }
    if (!inet_ntop(AF_INET, &mask, mask_str, INET_ADDRSTRLEN)) {
        perror("inet_ntop failed for mask");
        strncpy(mask_str, "INVALID", INET_ADDRSTRLEN);
    }

    // Debug logging
    // printf("[Routing Table] Adding Route: Destination=%s, Next Hop=%s, Mask=%s, Interface=%s\n",
    //        dest_str, next_hop_str, mask_str, iface);

    // Create the routing table entry
    struct in_addr dest_addr = { .s_addr = dest };
    struct in_addr next_hop_addr = { .s_addr = next_hop };
    struct in_addr mask_addr = { .s_addr = mask };
    sr_add_rt_entry(sr, dest_addr, next_hop_addr, mask_addr, iface);

    // Confirm the addition
    // printf("[Routing Table] Entry created successfully.\n");
}

/**
 * @brief Checks if a routing table entry exists for a given destination and next hop.
 *
 * This function traverses the routing table to find a matching entry for the
 * specified destination and next hop. If found, it returns a pointer to the
 * routing table entry; otherwise, it returns `NULL`.
 *
 * @param sr Pointer to the router instance.
 * @param ip_target Destination IP address (network byte order).
 * @param next_hop Next hop IP address (network byte order).
 * @return Pointer to the matching routing table entry, or `NULL` if not found.
 */
struct sr_rt* lookup_routing_table(struct sr_instance* sr, uint32_t ip_target, uint32_t next_hop) {
    // printf("[Routing Table] Checking for Entry...\n");

    char target_str[INET_ADDRSTRLEN], next_hop_str[INET_ADDRSTRLEN];

    // Convert target and next hop to string for debug purposes
    if (!inet_ntop(AF_INET, &ip_target, target_str, INET_ADDRSTRLEN)) {
        perror("inet_ntop failed for destination IP");
        return NULL;
    }
    if (!inet_ntop(AF_INET, &next_hop, next_hop_str, INET_ADDRSTRLEN)) {
        perror("inet_ntop failed for next hop IP");
        return NULL;
    }

    printf("  Destination: %s\n", target_str);
    printf("  Next Hop: %s\n", next_hop_str);

    // Traverse the routing table
    struct sr_rt* entry = sr->routing_table;
    while (entry != NULL) {
        char entry_dest_str[INET_ADDRSTRLEN], entry_next_hop_str[INET_ADDRSTRLEN];

        // Convert existing entry's destination and next hop to string
        if (!inet_ntop(AF_INET, &entry->dest.s_addr, entry_dest_str, INET_ADDRSTRLEN)) {
            perror("inet_ntop failed for entry destination");
            entry = entry->next;
            continue;
        }
        if (!inet_ntop(AF_INET, &entry->gw.s_addr, entry_next_hop_str, INET_ADDRSTRLEN)) {
            perror("inet_ntop failed for entry next hop");
            entry = entry->next;
            continue;
        }

        // Compare target and next hop with the current entry
        if (entry->dest.s_addr == ip_target && entry->gw.s_addr == next_hop) {
            // printf("[Routing Table] Match found: Destination=%s, Next Hop=%s\n", entry_dest_str, entry_next_hop_str);
            return entry;
        }

        entry = entry->next;
    }

    // printf("[Routing Table] No matching entry found for Destination=%s, Next Hop=%s\n", target_str, next_hop_str);
    return NULL;
}

/**
 * @brief Checks if a given subnet/mask combination is already implied by existing routes in the routing table.
 *
 * This function iterates through the router's current routing table to determine
 * if a new route would be redundant. It considers two scenarios:
 *
 * 1. **Default Route Scenario**: If an entry is the default route (`dest == 0` and `mask == 0`),
 *    it checks whether `(entry->gw.s_addr & mask) == subnet`. If so, the route is implied
 *    by the default route.
 *
 * 2. **Non-Default Routes**: It checks if `(entry->dest.s_addr & mask) == subnet` and
 *    `entry->mask.s_addr >= mask`. If this condition holds, an existing route already
 *    covers or matches the desired subnet/mask.
 *
 * @param sr     Pointer to the main router instance (`struct sr_instance`), which contains the routing table.
 * @param subnet The subnet (in network byte order) to be checked.
 * @param mask   The subnet mask (in network byte order).
 * @return `true` if the subnet is already implied by an existing route; `false` otherwise.
 */
bool route_already_implied(struct sr_instance* sr, uint32_t subnet, uint32_t mask) {
    char subnet_str[INET_ADDRSTRLEN], mask_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &subnet, subnet_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &mask, mask_str, INET_ADDRSTRLEN);
    printf("[Route Implied Check] Subnet=%s, Mask=%s, Checking Against Existing Routes...\n",
           subnet_str, mask_str);

    struct sr_rt* entry = sr->routing_table;
    while (entry) {
        char entry_subnet_str[INET_ADDRSTRLEN], entry_mask_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &entry->dest.s_addr, entry_subnet_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &entry->mask.s_addr, entry_mask_str, INET_ADDRSTRLEN);

        printf("  Comparing Against Route: Subnet=%s, Mask=%s\n", entry_subnet_str, entry_mask_str);

        // Skip default route
        if (entry->dest.s_addr == 0 && entry->mask.s_addr == 0) {
            
            // Check subnet of gate using mask
            if ((entry->gw.s_addr & mask) == subnet) {
                printf("  Match found: Default route is implied.\n");
                return true;
            }
            entry = entry->next;
            continue;
        }

        // Check if the route is implied by an existing route
        if ((entry->dest.s_addr & mask) == subnet && entry->mask.s_addr >= mask) {
            printf("  Match found: Route is implied.\n");
            return true;
        }

        entry = entry->next;
    }

    printf("  No matching implied route found.\n");
    return false;
}

/**
 * @brief Adds directly connected subnets to the routing table.
 *
 * This function iterates through the router's interfaces and adds directly connected
 * subnets to the routing table to ensure they are present at startup.
 *
 * @param sr Pointer to the router instance.
 */
void add_directly_connected_subnets(struct sr_instance* sr) {
    if (!sr || !sr->ospf_subsys || !sr->ospf_subsys->interfaces) {
        printf("[Error] Invalid router instance or OSPF subsystem.\n");
        return;
    }

    printf("[Routing Table] Adding directly connected subnets at startup...\n");

    struct pwospf_interface* iface = sr->ospf_subsys->interfaces;
    while (iface) {
        uint32_t subnet = iface->ip & iface->mask;

        char subnet_str[INET_ADDRSTRLEN], mask_str[INET_ADDRSTRLEN], iface_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &subnet, subnet_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &iface->mask, mask_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &iface->ip, iface_ip_str, INET_ADDRSTRLEN);

        printf("[Routing Table] Checking directly connected interface: %s, Interface IP: %s\n", iface->name, iface_ip_str);
        printf("  Calculated Subnet=%s, Mask=%s\n", subnet_str, mask_str);

        if (!lookup_routing_table(sr, subnet, 0) && !route_already_implied(sr, subnet, iface->mask)) {
            printf("[Routing Table] Adding directly connected route: Subnet=%s, Mask=%s, Interface=%s\n",
                subnet_str, mask_str, iface->name);
            create_rtable_entry(sr, subnet, 0, iface->mask, iface->name);
        } else {
            printf("[Routing Table] Skipping directly connected route for Subnet=%s, Mask=%s (Already exists).\n",
                subnet_str, mask_str);
        }

        iface = iface->next;
    }

    printf("[Routing Table] Directly connected subnets added.\n");
}

/**
 * @brief Updates an existing routing table entry.
 *
 * @param sr Pointer to the router instance.
 * @param entry Pointer to the routing table entry to update.
 * @param next_hop The new next hop for the route.
 * @param mask The new mask for the route.
 */
void update_rtable_entry(struct sr_instance* sr, struct sr_rt* entry, uint32_t next_hop, uint32_t mask, const char* iface) {
    entry->gw.s_addr = next_hop;
    entry->mask.s_addr = mask;
    strncpy(entry->interface, iface, sizeof(entry->interface) - 1);
    entry->interface[sizeof(entry->interface) - 1] = '\0';

    char subnet_str[INET_ADDRSTRLEN], next_hop_str[INET_ADDRSTRLEN], mask_str[INET_ADDRSTRLEN], iface_str[SR_IFACE_NAMELEN];
    inet_ntop(AF_INET, &entry->dest.s_addr, subnet_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &next_hop, next_hop_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &mask, mask_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &entry->interface, iface_str, SR_IFACE_NAMELEN);

    // printf("[Routing Table] Updated Entry: Destination=%s, Next Hop=%s, Mask=%s, Interface=%s\n",
    //        subnet_str, next_hop_str, mask_str, iface_str);
}

/**
 * @brief Looks up a routing entry in the routing table based on subnet only.
 *
 * @param sr Pointer to the router instance.
 * @param subnet Target subnet to search for.
 * @return Pointer to the routing table entry if a match is found; NULL otherwise.
 */
struct sr_rt* lookup_route_by_subnet(struct sr_instance* sr, uint32_t subnet) {
    // printf("[Routing Table] Checking for Entry by Subnet...\n");

    char subnet_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &subnet, subnet_str, INET_ADDRSTRLEN)) {
        perror("inet_ntop failed for subnet");
        return NULL;
    }
    // printf("  Subnet: %s\n", subnet_str);

    struct sr_rt* entry = sr->routing_table;
    while (entry != NULL) {
        char entry_dest_str[INET_ADDRSTRLEN];

        if (!inet_ntop(AF_INET, &entry->dest.s_addr, entry_dest_str, INET_ADDRSTRLEN)) {
            perror("inet_ntop failed for entry destination");
            entry = entry->next;
            continue;
        }

        // Compare the destination subnet
        if (entry->dest.s_addr == subnet) {
            // printf("[Routing Table] Match found: Subnet=%s\n", entry_dest_str);
            return entry;
        }

        entry = entry->next;
    }

    // printf("[Routing Table] No matching entry found for Subnet=%s\n", subnet_str);
    return NULL;
}
