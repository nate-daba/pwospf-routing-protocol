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

    return 0;
}


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

        // Clean up stale routers in the topology database
        printf("Cleaning up stale routers from topology database.\n");
        cleanup_topology_database(sr->ospf_subsys);

        pwospf_unlock(sr->ospf_subsys);

        // Sleep for HELLO_INTERVAL seconds
        sleep(HELLO_INTERVAL);
    }

    return NULL;
}

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
                pwospf_send_lsu(sr, NULL);
            }
            return;
        }
        pwospf_iface = pwospf_iface->next;
    }

    printf("No matching PWOSPF interface for HELLO packet received on %s\n", interface);
}

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

            // Mark topology as changed
            topology_changed = 1;
        }

        iface = iface->next;
    }

    // Trigger an LSU flood if the topology has changed
    if (topology_changed) {
        printf("Initiating Link State Update due to topology change.\n");
        pwospf_send_lsu(sr, NULL);

        // Reset the lsuint counter
        *last_lsu_time = now;
    }
}

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

int pwospf_validate_lsu(struct pwospf_subsys* subsys, uint32_t router_id, uint32_t seq) {
    assert(subsys);

    // Iterate through the topology database
    struct pwospf_router* entry = subsys->topology;
    while (entry) {
        if (entry->router_id == router_id) {
            // If entry exists, check the sequence number
            if (seq <= entry->last_sequence) {
                return 0; // Sequence number is stale or duplicate
            }
            return 1; // Sequence number is valid
        }
        entry = entry->next;
    }

    // If no entry exists for this router, consider it valid
    return 1;
}

void pwospf_handle_lsu(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
    struct ospfv2_hdr* ospf_hdr = (struct ospfv2_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + (ip_hdr->ip_hl * 4));
    struct ospfv2_lsu_hdr* lsu_hdr = (struct ospfv2_lsu_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + (ip_hdr->ip_hl * 4) + sizeof(struct ospfv2_hdr));
    struct ospfv2_lsu* lsu_adv = (struct ospfv2_lsu*)((uint8_t*)lsu_hdr + sizeof(struct ospfv2_lsu_hdr));

    uint32_t num_links = ntohl(lsu_hdr->num_adv);

    uint32_t seq = lsu_hdr->seq; // Convert from network byte order
    printf("Received LSU from Router ID: %s, Seq: %u, Links: %u\n",
       inet_ntoa(*(struct in_addr*)&ospf_hdr->rid), seq, num_links);

    struct pwospf_subsys* subsys = sr->ospf_subsys;

    // Step 1: Discard LSUs generated by this router
    if (ospf_hdr->rid == subsys->router_id) {
        printf("Discarded LSU packet: self-originated.\n");
        return;
    }

    // Step 2: Check sequence number to determine if the LSU is stale
    struct pwospf_router* router_entry = subsys->topology;
    while (router_entry) {
        if (router_entry->router_id == ospf_hdr->rid) {
            if (seq <= router_entry->last_sequence) {
                printf("Discarded LSU packet: stale or redundant sequence number.\n");
                return;
            }

            // Count current links in the router's interface list
            uint32_t current_links = 0;
            struct pwospf_interface* iface = router_entry->interfaces;
            while (iface) {
                current_links++;
                iface = iface->next;
            }
            // print interfaces of the router, current_links, and num_links
            printf("Current links: %d, num_links: %d\n", current_links, num_links);
            // print detailed information in lsu_adv
            uint32_t router_id = ospf_hdr->rid;
            uint32_t neighbor_ip = ip_hdr->ip_src.s_addr;
            print_lsu_debug_info(router_id, neighbor_ip, num_links, lsu_adv);

            int topology_changed = 0;
            struct pwospf_interface* current_iface = router_entry->interfaces;

            // Compare each interface with the received LSU advertisements
            for (uint32_t i = 0; i < num_links; i++) {
                if (!current_iface || current_iface->ip != lsu_adv[i].subnet || current_iface->mask != lsu_adv[i].mask || current_iface->neighbor.router_id != lsu_adv[i].rid) {
                    topology_changed = 1;
                    break;
                }
                current_iface = current_iface->next;
            }

            // If the topology hasn't changed, discard the packet
            if (!topology_changed && current_links == num_links) {
                printf("Discarded LSU packet: no topology changes detected. However, sequence number is updated!\n");
                router_entry->last_sequence = seq; // Update sequence number
                router_entry->last_updated = time(NULL); // Update last updated time
                return;
            }
            printf("Topology has changed!! Updating the database.\n");
            printf("Updating topology database for Router ID: %s\n", inet_ntoa(*(struct in_addr*)&ospf_hdr->rid));
            router_entry->last_sequence = seq;
            router_entry->last_updated = time(NULL); // Update last updated time
            // Free old neighbor list and rebuild it
            struct pwospf_interface* old_iface = router_entry->interfaces;
            while (old_iface) {
                struct pwospf_interface* next_iface = old_iface->next;
                free(old_iface);
                old_iface = next_iface;
            }

            router_entry->interfaces = NULL; // Reset interfaces
            for (uint32_t i = 0; i < num_links; i++) {
                struct pwospf_interface* new_iface = malloc(sizeof(struct pwospf_interface));
                if (!new_iface) {
                    perror("Failed to allocate memory for interface");
                    return;
                }
                memset(new_iface, 0, sizeof(struct pwospf_interface));
                new_iface->ip = lsu_adv[i].subnet;
                new_iface->mask = lsu_adv[i].mask;
                new_iface->neighbor.router_id = lsu_adv[i].rid;
                new_iface->next = router_entry->interfaces;
                router_entry->interfaces = new_iface;
            }
            printf("Topology database updated successfully.\n");
            update_next_hop(router_entry, ip_hdr->ip_src.s_addr, ospf_hdr->rid);
            print_topology(subsys);
            return; // Exit after updating the existing router entry
        }
        router_entry = router_entry->next;
    }

    // Step 3: Add new router to the topology database
    printf("Creating new topology entry for Router ID: %s\n", inet_ntoa(*(struct in_addr*)&ospf_hdr->rid));
    struct pwospf_router* new_router = malloc(sizeof(struct pwospf_router));
    if (!new_router) {
        perror("Failed to allocate memory for new topology entry");
        return;
    }
    memset(new_router, 0, sizeof(struct pwospf_router));
    new_router->router_id = ospf_hdr->rid;
    new_router->area_id = subsys->area_id; // Assuming the same area for all routers
    new_router->last_sequence = seq;
    new_router->last_updated = time(NULL);
    new_router->interfaces = NULL;

    for (uint32_t i = 0; i < num_links; i++) {
        struct pwospf_interface* new_iface = malloc(sizeof(struct pwospf_interface));
        if (!new_iface) {
            perror("Failed to allocate memory for interface");
            free(new_router); // Avoid memory leaks
            return;
        }
        memset(new_iface, 0, sizeof(struct pwospf_interface)); // Initialize all fields to 0

        new_iface->ip = lsu_adv[i].subnet;
        new_iface->mask = lsu_adv[i].mask;
        new_iface->neighbor.router_id = lsu_adv[i].rid;
        new_iface->neighbor.next_hop = 0; // Explicitly set next_hop to 0 (default)

        new_iface->next = new_router->interfaces;
        new_router->interfaces = new_iface;
    }

    new_router->next = subsys->topology;
    subsys->topology = new_router;

    printf("New topology entry created successfully.\n");
    update_next_hop(new_router, ip_hdr->ip_src.s_addr, ospf_hdr->rid);
    print_topology(subsys);

    // Step 4: Recalculate forwarding table
    // pwospf_recalculate_routing_table(sr);

    // Step 5: Forward LSU to other neighbors (flooding)
    printf("Flooding LSU to other neighbors except interface: %s\n", interface);

    // Decrement TTL before forwarding
    lsu_hdr->ttl--;

    if (lsu_hdr->ttl <= 0) {
        printf("LSU packet TTL expired. Dropping packet.\n");
        return; // Drop the packet if TTL is zero or less
    }

    // Recalculate OSPF checksum
    ospf_hdr->csum = 0; // Clear the checksum field before recalculation

    size_t ospf_payload_len = len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip);
    uint16_t* ospf_payload = malloc(ospf_payload_len);
    if (!ospf_payload) {
        perror("Failed to allocate memory for aligned buffer");
        return;
    }
    memcpy(ospf_payload, ospf_hdr, ospf_payload_len);

    ospf_hdr->csum = checksum_pwospf(ospf_payload, ospf_payload_len / 2);
    free(ospf_payload);

    // Flood to all neighbors except the incoming interface
    pwospf_send_lsu(sr, interface);
}

// PWOSPF-specific checksum calculation
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
            if (!inet_ntop(AF_INET, &iface->ip, subnet_str, INET_ADDRSTRLEN)) {
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
            if (!inet_ntop(AF_INET, &iface->neighbor.next_hop, next_hop_str, INET_ADDRSTRLEN)) {
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

void cleanup_topology_database(struct pwospf_subsys* subsys) {
    time_t now = time(NULL);
    struct pwospf_router** current = &subsys->topology;
    int topology_changed = 0;
    while (*current) {
        struct pwospf_router* router = *current;
        if (difftime(now, router->last_updated) > LSU_TIMEOUT) {
            printf("Removing stale router entry: Router ID: %s\n",
                   inet_ntoa(*(struct in_addr*)&router->router_id));
            
            // Remove the router from the list
            *current = router->next;
            topology_changed = 1;
            // Free the associated interfaces
            struct pwospf_interface* iface = router->interfaces;
            while (iface) {
                struct pwospf_interface* next_iface = iface->next;
                free(iface);
                iface = next_iface;
            }

            // Free the router entry
            free(router);
        } else {
            current = &router->next; // Move to the next router
        }
    }
    if (topology_changed) {
        printf("Topology database cleaned up successfully.\n");
        print_topology(subsys);
    }
}

/**
 * Updates the next_hop field for the given router's interfaces.
 * This is based on the source of the LSU (neighbor IP).
 */
void update_next_hop(struct pwospf_router* router, uint32_t received_from_ip, uint32_t sender_router_id) {
    if (!router) {
        printf("update_next_hop: Router is NULL.\n");
        return;
    }

    char router_id_str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &router->router_id, router_id_str, INET_ADDRSTRLEN)) {
        perror("inet_ntop failed for router_id");
        return;
    }

    printf("update_next_hop: Updating next_hop for Router ID: %s\n", router_id_str);

    struct pwospf_interface* iface = router->interfaces;

    if (!iface) {
        printf("update_next_hop: No interfaces for Router ID: %s\n", router_id_str);
        return;
    }

    int updated = 0; // Track if any updates are made
    while (iface) {
        char iface_ip_str[INET_ADDRSTRLEN];
        char neighbor_id_str[INET_ADDRSTRLEN];
        char sender_router_id_str[INET_ADDRSTRLEN];

        if (!inet_ntop(AF_INET, &iface->ip, iface_ip_str, INET_ADDRSTRLEN)) {
            perror("inet_ntop failed for interface IP");
            iface = iface->next;
            continue;
        }
        if (!inet_ntop(AF_INET, &iface->neighbor.router_id, neighbor_id_str, INET_ADDRSTRLEN)) {
            perror("inet_ntop failed for Neighbor ID");
            iface = iface->next;
            continue;
        }
        if (!inet_ntop(AF_INET, &sender_router_id, sender_router_id_str, INET_ADDRSTRLEN)) {
            perror("inet_ntop failed for Sender Router ID");
            iface = iface->next;
            continue;
        }

        printf("  Checking Interface: %s, Neighbor ID: %s, Sender Router ID: %s\n",
               iface_ip_str, neighbor_id_str, sender_router_id_str);

        // If the Neighbor ID matches the sender_router_id, update next_hop
        if (iface->neighbor.router_id == sender_router_id) {
            iface->neighbor.next_hop = received_from_ip;
            updated = 1;

            char next_hop_str[INET_ADDRSTRLEN];
            if (!inet_ntop(AF_INET, &received_from_ip, next_hop_str, INET_ADDRSTRLEN)) {
                perror("inet_ntop failed for next_hop");
            } else {
                printf("    Match found! Updated Next Hop for Interface IP: %s to: %s\n",
                       iface_ip_str, next_hop_str);
            }
        } else {
            printf("    No match. Neighbor ID: %s does not match Sender Router ID: %s\n",
                   neighbor_id_str, sender_router_id_str);
        }

        iface = iface->next;
    }

    if (!updated) {
        printf("update_next_hop: No updates made for Router ID: %s.\n", router_id_str);
    }
}
