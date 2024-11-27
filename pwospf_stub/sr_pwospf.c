/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
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

/* -- declaration of main thread function for pwospf subsystem --- */
static void* pwospf_run_thread(void* arg);

/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Sets up the internal data structures for the pwospf subsystem
 *
 * You may assume that the interfaces have been created and initialized
 * by this point.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance* sr)
{
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);


    /* -- handle subsystem initialization here! -- */
    struct pwospf_subsys* subsys = sr->ospf_subsys;

    subsys->seq = 0; // Initialize sequence number

    /* -- set up router ID -- */
    // Set Router ID to the IP of the first interface
    struct sr_if* first_interface = sr->if_list;
    if (first_interface) {
        subsys->router_id = first_interface->ip;
    } else {
        fprintf(stderr, "Error: No interfaces available to determine Router ID\n");
        subsys->router_id = 0; // Fallback value
    }

    // Set the area ID (single area for this project)
    subsys->area_id = 0;

    // Initialize the interface list in the PWOSPF subsystem
    subsys->interfaces = NULL;
    struct sr_if* iface = sr->if_list;
    struct pwospf_interface** pwospf_iface_ptr = &(subsys->interfaces);
    while (iface) {
        // Allocate and populate PWOSPF interface structure
        struct pwospf_interface* pwospf_iface = (struct pwospf_interface*)malloc(sizeof(struct pwospf_interface));
        strncpy(pwospf_iface->name, iface->name, SR_IFACE_NAMELEN); // Copy the name
        pwospf_iface->ip = iface->ip;
        pwospf_iface->mask = iface->mask;
        pwospf_iface->helloint = HELLO_INTERVAL;
        pwospf_iface->neighbors = NULL;
        pwospf_iface->next = NULL;

        *pwospf_iface_ptr = pwospf_iface; // Append to the list
        pwospf_iface_ptr = &(pwospf_iface->next); // Move to the next pointer
        iface = iface->next; // Move to the next interface
    }

    /* -- start thread subsystem -- */
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr) != 0) {
        perror("pthread_create");
        assert(0);
    }

    printf("PWOSPF subsystem initialized with Router ID: %s\n",
           inet_ntoa(*(struct in_addr*)&subsys->router_id));   

    return 0; /* success */
} /* -- pwospf_init -- */


/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Main thread of pwospf subsystem.
 *
 *---------------------------------------------------------------------*/

static void* pwospf_run_thread(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;
    time_t last_lsu_time = time(NULL); // Initialize last LSU time
    
    while(1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */
        pwospf_lock(sr->ospf_subsys);
        // pwospf_print_subsys(sr->ospf_subsys);
        // Periodically send HELLO messages
        struct pwospf_interface* iface = sr->ospf_subsys->interfaces;
        while (iface) {
            pwospf_send_hello(sr, iface);
            pwospf_remove_timed_out_neighbors(iface); // Check for timed out neighbors
            iface = iface->next;
        }
        // Check if it's time to send an LSU
        time_t now = time(NULL);
        if (difftime(now, last_lsu_time) >= LSUINT) {
            printf("Sending periodic LSU.\n");
            pwospf_send_lsu(sr); // Call the function to send LSU
            last_lsu_time = now; // Reset the LSU timer
        }
        printf(" pwospf subsystem sleeping \n");
        pwospf_unlock(sr->ospf_subsys);
        sleep(HELLO_INTERVAL);
        printf(" pwospf subsystem awake \n");
    };
    return NULL;
} /* -- run_ospf_thread -- */

void pwospf_print_subsys(struct pwospf_subsys* subsys) {
    assert(subsys);

    printf("\nPWOSPF Subsystem State:\n");
    printf("Router ID: %s\n", inet_ntoa(*(struct in_addr*)&subsys->router_id));
    printf("Area ID: %d\n", subsys->area_id);

    printf("Interfaces:\n");
    struct pwospf_interface* iface = subsys->interfaces;
    while (iface) {
        printf("  - IP: %s\n", inet_ntoa(*(struct in_addr*)&iface->ip));
        printf("    Mask: %s\n", inet_ntoa(*(struct in_addr*)&iface->mask));
        printf("    HELLO Interval: %d\n", iface->helloint);
        iface = iface->next;
    }
    printf("\n");
}

void pwospf_send_hello(struct sr_instance* sr, struct pwospf_interface* iface) {
    assert(sr);
    assert(iface);

    size_t packet_len = sizeof(struct sr_ethernet_hdr) +
                        sizeof(struct ip) +
                        sizeof(struct ospfv2_hdr) +
                        sizeof(struct ospfv2_hello_hdr);

    uint8_t* packet = (uint8_t*)malloc(packet_len);
    memset(packet, 0, packet_len);

    // Fill Ethernet header
    struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)packet;
    memset(eth_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN); // Broadcast
    struct sr_if* sr_iface = sr_get_interface(sr, iface->name);
    memcpy(eth_hdr->ether_shost, sr_iface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ETHERTYPE_IP);

    // Fill IP header
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

    // Fill OSPF header
    struct ospfv2_hdr* ospf_hdr = (struct ospfv2_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    ospf_hdr->version = PWOSPF_VERSION;
    ospf_hdr->type = PWOSPF_TYPE_HELLO;
    ospf_hdr->len = htons(sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr));
    ospf_hdr->rid = sr->ospf_subsys->router_id; // Correctly use the router's Router ID
    ospf_hdr->aid = 0; // Single area
    ospf_hdr->autype = 0; // No authentication
    ospf_hdr->audata = 0;

    // Fill HELLO header
    struct ospfv2_hello_hdr* hello_hdr = (struct ospfv2_hello_hdr*)(packet + sizeof(struct sr_ethernet_hdr) +
                                                                    sizeof(struct ip) +
                                                                    sizeof(struct ospfv2_hdr));
    hello_hdr->nmask = iface->mask;
    hello_hdr->helloint = htons(HELLO_INTERVAL);

    // Send the packet
    sr_send_packet(sr, packet, packet_len, sr_iface->name);

    printf("Sent HELLO packet from interface: %s (IP: %s)\n",
           sr_iface->name,
           inet_ntoa(*(struct in_addr*)&iface->ip));

    free(packet); // Free allocated memory
}

void pwospf_update_neighbor(struct pwospf_interface* iface, uint32_t router_id, uint32_t neighbor_ip) {
    assert(iface);

    struct pwospf_neighbor* current = iface->neighbors;
    struct pwospf_neighbor* prev = NULL;

    char router_id_str[INET_ADDRSTRLEN];
    char neighbor_ip_str[INET_ADDRSTRLEN];
    strcpy(router_id_str, inet_ntoa(*(struct in_addr*)&router_id));
    strcpy(neighbor_ip_str, inet_ntoa(*(struct in_addr*)&neighbor_ip));

    // Search for the neighbor
    while (current) {
        if (current->router_id == router_id) {
            // Update the neighbor's info and timestamp
            current->neighbor_ip = neighbor_ip;
            current->last_hello_received = time(NULL);
            printf("Updated neighbor: Router ID: %s, Neighbor IP: %s\n",
                   router_id_str, neighbor_ip_str);
            return;
        }
        prev = current;
        current = current->next;
    }

    // Neighbor not found, add a new one
    struct pwospf_neighbor* new_neighbor = (struct pwospf_neighbor*)malloc(sizeof(struct pwospf_neighbor));
    new_neighbor->router_id = router_id;
    new_neighbor->neighbor_ip = neighbor_ip;
    new_neighbor->last_hello_received = time(NULL);
    new_neighbor->next = NULL;

    if (prev) {
        prev->next = new_neighbor;
    } else {
        iface->neighbors = new_neighbor;
    }

    printf("Added new neighbor: Router ID: %s, IP: %s\n",
           router_id_str, neighbor_ip_str);
}

void pwospf_remove_timed_out_neighbors(struct pwospf_interface* iface) {
    assert(iface);

    struct pwospf_neighbor* current = iface->neighbors;
    struct pwospf_neighbor* prev = NULL;

    time_t now = time(NULL);

    char router_id_str[INET_ADDRSTRLEN];  // Buffer for Router ID string
    char neighbor_ip_str[INET_ADDRSTRLEN]; // Buffer for Neighbor IP string

    while (current) {
        if (difftime(now, current->last_hello_received) > NEIGHBOR_TIMEOUT) {
            // Convert Router ID and Neighbor IP to strings
            inet_ntop(AF_INET, &current->router_id, router_id_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &current->neighbor_ip, neighbor_ip_str, INET_ADDRSTRLEN);

            printf("Removing timed-out neighbor: Router ID: %s, IP: %s\n", router_id_str, neighbor_ip_str);

            // Remove the neighbor from the list
            if (prev) {
                prev->next = current->next;
            } else {
                iface->neighbors = current->next;
            }

            struct pwospf_neighbor* to_free = current;
            current = current->next;
            free(to_free);
        } else {
            prev = current;
            current = current->next;
        }
    }
}

void pwospf_send_lsu(struct sr_instance* sr) {
    struct pwospf_subsys* subsys = sr->ospf_subsys;
    assert(subsys);

    struct pwospf_interface* iface = subsys->interfaces;
    while (iface) {
        // Build LSU packet
        uint32_t num_links = 3; // Number of links (including the stub link)
        size_t packet_len = sizeof(struct sr_ethernet_hdr) +
                            sizeof(struct ip) +
                            sizeof(struct ospfv2_hdr) +
                            sizeof(struct pwospf_lsu) +
                            num_links * sizeof(struct pwospf_lsu_link);
        uint8_t* packet = (uint8_t*)malloc(packet_len);

        // Fill Ethernet header
        struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*)packet;
        memset(eth_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN); // Broadcast
        memcpy(eth_hdr->ether_shost, sr_get_interface(sr, iface->name)->addr, ETHER_ADDR_LEN);
        eth_hdr->ether_type = htons(ETHERTYPE_IP);

        // Fill IP header
        struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
        ip_hdr->ip_v = 4;
        ip_hdr->ip_hl = 5;
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(packet_len - sizeof(struct sr_ethernet_hdr));
        ip_hdr->ip_ttl = 64;
        ip_hdr->ip_p = 89; // OSPF Protocol
        ip_hdr->ip_src.s_addr = iface->ip;
        ip_hdr->ip_dst.s_addr = inet_addr("224.0.0.5");
        ip_hdr->ip_sum = checksum(ip_hdr, ip_hdr->ip_hl * 4);

        // Fill OSPF header
        struct ospfv2_hdr* ospf_hdr = (struct ospfv2_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
        ospf_hdr->version = PWOSPF_VERSION;
        ospf_hdr->type = PWOSPF_TYPE_LSU;
        ospf_hdr->len = htons(sizeof(struct ospfv2_hdr) + sizeof(struct pwospf_lsu) + num_links * sizeof(struct pwospf_lsu_link));
        ospf_hdr->rid = subsys->router_id;
        ospf_hdr->aid = subsys->area_id;
        ospf_hdr->autype = 0;
        ospf_hdr->audata = 0;

        // Fill LSU header
        struct pwospf_lsu* lsu = (struct pwospf_lsu*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
        lsu->seq = htonl(subsys->seq++);
        lsu->num_links = htonl(num_links);

        struct pwospf_lsu_link* link = (struct pwospf_lsu_link*)(lsu->links);
        link->link_id = iface->ip;
        link->link_data = iface->mask;
        link->type = 2; // Stub link
        link->metric = 1; // Cost

        sr_send_packet(sr, packet, packet_len, iface->name);
        printf("Sent LSU from interface: %s\n", iface->name);
        free(packet);
        iface = iface->next;
    }
}

void pwospf_handle_lsu(struct sr_instance* sr, struct ospfv2_hdr* ospf_hdr, uint8_t* packet) {
    struct pwospf_lsu* lsu = (struct pwospf_lsu*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
    uint32_t seq = ntohl(lsu->seq);
    uint32_t num_links = ntohl(lsu->num_links);

    printf("Received LSU from Router ID: %s, Seq: %u, Links: %u\n",
           inet_ntoa(*(struct in_addr*)&ospf_hdr->rid), seq, num_links);

    // Check and update the LSDB
    // Forward LSU if new
}

