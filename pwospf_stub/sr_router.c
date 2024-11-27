/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 * #1693354266
 * 
 **********************************************************************/
#include <time.h>
#include <stdlib.h>  
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <net/if_arp.h>  

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_pwospf.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"

struct arp_cache_entry* arp_cache = NULL; /* Global ARP cache (linked list) */

/* Structure to hold packets waiting for ARP replies */
struct sr_packet {
    uint8_t *buf;                  /* Buffer containing the packet */
    unsigned int len;              /* Length of the packet */
    char iface[SR_IFACE_NAMELEN];  /* Interface the packet was received on */
    uint32_t next_hop_ip;          /* The next hop IP address */
    struct sr_packet *next;        /* Pointer to the next packet in the queue */
};

/* Head of the packet queue */
struct sr_packet *packet_queue = NULL;

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

   /* moved to sr_vns_comm.c, after HWINFO has been received and processed */
   /* pwospf_init(sr); */

    /* print all interfaces and their info */
    // sr_print_if_list(sr);
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(
        struct sr_instance* sr, /* allows access to this router’s interfaces and routing/forwarding table*/
        uint8_t * packet/* points to the buffer containing the incoming packet. */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    /* determine to forward or not */
    struct sr_ethernet_hdr *e_hdr = (struct sr_ethernet_hdr *)packet;
    uint16_t ethtype = e_hdr->ether_type;
    struct sr_if* iface = sr_get_interface(sr, interface);
    /* If the incoming packet is an IP packet (based on EtherType), 
    the router needs to carry out the following steps: */
    if (ethtype == htons(ETHERTYPE_IP)) 
    {
        printf("IP packet\n"); 
        struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));

        /* 1. If the destination IP is one of the router’s */
        if (to_myself(sr, ip_hdr->ip_dst.s_addr) == 1)
        {
            uint8_t ip_p = ip_hdr->ip_p;
            /* a. If the packet is an ICMP echo request,  */
            if (ip_p == IPPROTO_ICMP)
            {
                printf("ICMP packet\n");
                /* Cast ICMP header */
                struct sr_icmp_hdr *icmp_hdr = (struct sr_icmp_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + (ip_hdr->ip_hl * 4));

                /* Check if it's an echo request */
                if (icmp_hdr->icmp_type == ICMP_ECHO_REQUEST)
                {
                    
                    printf("ICMP echo request\n");
                    /* the router should respond with an ICMP echo reply.*/

                    /* Modify Ethernet header to send an echo reply */
                    memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, 6);
                    memcpy(e_hdr->ether_shost, iface->addr, 6);

                    /* Modify ICMP header to send an echo reply */
                    icmp_hdr->icmp_type = ICMP_ECHO_REPLY;
                    icmp_hdr->icmp_code = 0;
                    icmp_hdr->icmp_sum = 0;
                    icmp_hdr->icmp_sum = checksum((void*)icmp_hdr, len - (sizeof(struct sr_ethernet_hdr) + (ip_hdr->ip_hl * 4)));

                    /* Swap IP source and destination */
                    struct in_addr temp = ip_hdr->ip_src;
                    ip_hdr->ip_src = ip_hdr->ip_dst;
                    ip_hdr->ip_dst = temp;

                    /* Recalculate IP checksum */
                    ip_hdr->ip_sum = 0;
                    ip_hdr->ip_sum = checksum((void*)ip_hdr, ip_hdr->ip_hl * 4);

                    /* Send the ICMP reply packet */
                    sr_send_packet(sr, packet, len, interface);
                    printf("Sent ICMP echo reply\n");
                }
                else if (icmp_hdr->icmp_type == ICMP_ECHO_REPLY)
                {
                    printf("ICMP echo reply\n");
                }
                else 
                {
                    printf("Non-echo ICMP packet. Discarding packet ... \n");
                    return;
                }
            }
            /* b. Otherwise discard the packet, i.e., return from the function without further
            processing. */
            else 
            {
                printf("Non-ICMP packet. Discarding packet ... \n");
                return;
            }
        }
        /* check if packet is pwospf packet */
        else if (ip_hdr->ip_p == 89) { // OSPF Protocol
            printf("PWOSPF packet\n");
            pwospf_handle_packet(sr, packet, len, interface);
        }
        /* IP packet is not for me. Forward it using routing table. */
        else 
        {    /* 2. Decrement TTL by 1.*/
            ip_hdr->ip_ttl -= 1;
            /* a. If the result is 0, discard the packet */
            if (ip_hdr->ip_ttl == 0)
            {
                printf("TTL = 0. Discarding packet ... \n");
                return;
            }
            /* b. Otherwise, calculate header checksum and save the result to the checksum field.*/
            else 
            {
                ip_hdr->ip_sum = 0;
                ip_hdr->ip_sum = checksum((void*)ip_hdr, ip_hdr->ip_hl * 4);
            }
            /* 3. Use the IP destination address to look up the routing table, find the matching
                entry to be used for packet forwarding.*/
            printf("Routing table \n");
            sr_print_routing_table(sr);
            uint32_t nexthop;
            char out_iface[SR_IFACE_NAMELEN];
            printf("Looking up routing table to find match for %s\n", inet_ntoa(ip_hdr->ip_dst));
            if (lookup_rt(sr, ip_hdr->ip_dst.s_addr, &nexthop, out_iface) == 0) 
            {
                printf("Match found in routing table \n");
                printf("Next hop: %s\n", inet_ntoa(*(struct in_addr*)&nexthop));
                printf("Interface: %s\n", out_iface);
                printf("Current ARP cache \n");
                sr_print_arp_cache();
                /* Check ARP cache for the next hop's MAC address */
                unsigned char mac[ETHER_ADDR_LEN];
                if (nexthop == 0) 
                {
                    /* Next hop is 0.0.0.0, meaning the destination is directly reachable */
                    nexthop = ip_hdr->ip_dst.s_addr;  /* Set next hop to the destination IP */
                }
                printf("Checking ARP cache for MAC address of %s\n", inet_ntoa(*(struct in_addr*)&nexthop));
                if (check_arp_cache(nexthop, mac)) 
                {
                    printf("ARP cache hit: Using MAC address from cache\n");

                    /* Modify Ethernet header with the cached MAC address */
                    struct sr_if* o_iface = sr_get_interface(sr, out_iface);
                    memcpy(e_hdr->ether_shost, o_iface->addr, 6);  /* Source MAC */
                    memcpy(e_hdr->ether_dhost, mac, 6);              /* Destination MAC */

                    /* Forward the packet */
                    printf("Forwarded packet \n");
                    sr_send_packet(sr, packet, len, out_iface);
                } else 
                {
                    /* Save packet in queue to forward it later when arp reply is received */
                    printf("ARP cache miss t\n");
                    /* Send ARP request if cache miss */
                    if (nexthop == 0) 
                    {
                        /* Next hop is 0.0.0.0, meaning the destination is directly reachable */
                        nexthop = ip_hdr->ip_dst.s_addr;  /* Set next hop to the destination IP */
                        printf("Updating next hop to destination IP %s because it's 0.0.0.0 \n", inet_ntoa(*(struct in_addr*)&nexthop));
                    }
                    printf("Queuing current packet ... \n");
                    queue_pkt(packet, len, out_iface, nexthop);
                    printf("Sending ARP request to %s ... \n", inet_ntoa(*(struct in_addr*)&nexthop));
                    send_arp_request(sr, nexthop, sr_get_interface(sr, out_iface));
                }
            }
            else 
            {
                printf("No matching route found in routing table. Dropping packet.\n");
            }
        }
    } 
    /* Process ARP packet */
    else if (ethtype == htons(ETHERTYPE_ARP)) 
    {
        printf("ARP packet\n");
        struct sr_arphdr *a_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));
        if (a_hdr->ar_op == htons(ARP_REQUEST)) 
        {
            printf("ARP request\n");
            if (a_hdr->ar_tip == iface->ip) 
            {
                printf("ARP request for me\n");
                /* ========================================================== */
                /* Construct ARP reply */
                /* ========================================================== */
                /* 1. Construct Ethernet header */
                uint8_t mac_dst[6]; // Create a local array to hold the original sender's MAC address (THIS ALMOST DROVE ME CRAZY!!)
                memcpy(mac_dst, e_hdr->ether_shost, 6); // Copy the original sender's MAC (from ARP request) into mac_dst       
                uint8_t *mac_src = iface->addr; // Router's MAC (our interface) 32:8e
                
                memcpy(e_hdr->ether_dhost, mac_dst, 6); // Set destination MAC in Ethernet header (original sender) ba:be:
                memcpy(e_hdr->ether_shost, mac_src, 6); // Set source MAC in Ethernet header (router's MAC) 32:8e
                e_hdr->ether_type = htons(ETHERTYPE_ARP); // Set Ethernet type to ARP

                /* 2. Construct ARP header */
                a_hdr->ar_op = htons(ARP_REPLY); // Set operation to ARP reply
                memcpy(a_hdr->ar_tha, mac_dst, 6); // Set target hardware address (original sender's MAC)
                memcpy(a_hdr->ar_sha, mac_src, 6); // Set sender hardware address (router's MAC)
                
                uint32_t s_ip = a_hdr->ar_sip; // Save sender IP address (original sender's IP)
                a_hdr->ar_sip = iface->ip; // Set sender IP address (router's IP)
                a_hdr->ar_tip = s_ip; // Set target IP address (original sender's IP)

                /* ========================================================== */
                /* Send out ARP reply */
                /* ========================================================== */
                sr_send_packet(sr, packet, len, interface);
                printf("Sent ARP reply\n");

            } else {
                printf("ARP request not for me\n");
            }
        } 
        else if (a_hdr->ar_op == htons(ARP_REPLY)) 
        {
            printf("ARP reply received\n");
            process_arp_reply(sr, a_hdr); /* Process and update ARP cache */
            printf("Current ARP cache \n");
            sr_print_arp_cache();
            /* Check packet buffer and send out packets from buffer by looking up arp cache for destination IP*/
        } 
        else {
            printf("Unknown ARP packet\n");
        }
    } 
    else 
    {
        printf("Unknown packet\n");
    }
}/* end sr_ForwardPacket */

void pwospf_handle_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
    struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
    struct ospfv2_hdr* ospf_hdr = (struct ospfv2_hdr*)(packet + sizeof(struct sr_ethernet_hdr) + (ip_hdr->ip_hl * 4));
    // Handle HELLO packets
    if (ospf_hdr->type == PWOSPF_TYPE_HELLO) {
        printf("Received PWOSPF HELLO packet.\n");

        struct sr_if* iface = sr_get_interface(sr, interface);
        if (iface) {
            struct pwospf_interface* pwospf_iface = sr->ospf_subsys->interfaces;
            while (pwospf_iface) {
                if (pwospf_iface->ip == iface->ip) {
                    // Pass the Router ID and the Neighbor IP to update the neighbor table
                    pwospf_update_neighbor(pwospf_iface, ospf_hdr->rid, ip_hdr->ip_src.s_addr);
                    break;
                }
                pwospf_iface = pwospf_iface->next;
            }
        }
    }
    // Handle LSU packets 
    else if (ospf_hdr->type == PWOSPF_TYPE_LSU) {
        printf("Received PWOSPF LSU packet.\n");

        struct pwospf_lsu_hdr* lsu_hdr = (struct pwospf_lsu_hdr*)((uint8_t*)ospf_hdr + sizeof(struct ospfv2_hdr));

        // Step 1: Validate Sequence Number
        // if (!pwospf_validate_lsu(sr->ospf_subsys, ospf_hdr->rid, lsu_hdr->seq)) {
        //     printf("Discarded LSU packet: stale sequence number.\n");
        //     return;
        // }

        // Step 2: Update Topology Database
        // pwospf_update_topology(sr->ospf_subsys, ospf_hdr->rid, lsu_hdr);

        // Step 3: Recompute Routing Table
        // pwospf_recompute_routing_table(sr);

        // Step 4: Forward the LSU Packet
        // pwospf_forward_lsu(sr, packet, len, interface);
    }
    // Handle other PWOSPF packet types
    else {
        printf("Unhandled PWOSPF packet type: %d\n", ospf_hdr->type);
    }
}

/* Function to perform the routing table lookup using the Longest Prefix Match */
int lookup_rt(struct sr_instance* sr, uint32_t dest_ip, uint32_t* nexthop, char* out_iface) {
    struct sr_rt* rt_walker = sr->routing_table;
    struct sr_rt* best_match = NULL;
    uint32_t longest_mask = 0;

    /* Iterate through the routing table */
    while (rt_walker) {
        /* Check if the destination IP matches using the mask */
        if ((dest_ip & rt_walker->mask.s_addr) == (rt_walker->dest.s_addr & rt_walker->mask.s_addr)) {
            /* Find the entry with the longest mask (largest number of bits in the mask) */
            if (ntohl(rt_walker->mask.s_addr) >= longest_mask) {
                longest_mask = ntohl(rt_walker->mask.s_addr);
                best_match = rt_walker;
            }
        }
        /* Move to the next entry in the routing table */
        rt_walker = rt_walker->next;
    }

    /* If a match is found, set the next hop and interface */
    if (best_match) {
        *nexthop = best_match->gw.s_addr;
        strncpy(out_iface, best_match->interface, SR_IFACE_NAMELEN);
        return 0; /* Success */
    }

    /* If no match is found, set nexthop and interface to -1 */
    *nexthop = -1;
    strncpy(out_iface, "-1", SR_IFACE_NAMELEN);
    return -1; /* No match found */
}

/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
/* Function to calculate ICMP checksum */
uint16_t checksum(void* vdata, size_t length)
{
    char* data = (char*)vdata;
    uint32_t acc = 0;

    // Handle complete 16-bit blocks
    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }

    // Handle any left-over byte
    if (length & 1) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }

    // Return the checksum
    return htons(~acc & 0xffff);
}

void process_arp_reply(struct sr_instance* sr, struct sr_arphdr* arp_reply) {
    /* Extract IP and MAC from the ARP reply */
    uint32_t ip = arp_reply->ar_sip;
    unsigned char* mac = arp_reply->ar_sha;

    /* Update the ARP cache */
    update_arp_cache(sr, ip, mac);

    /* Forward any queued packets waiting for this ARP reply */
    send_queued_pkts(sr, ip, mac);
}

void update_arp_cache(struct sr_instance* sr, uint32_t ip, unsigned char* mac) {
    struct arp_cache_entry* entry = arp_cache;
    struct timeval now;
    gettimeofday(&now, NULL);  /* Get the current time */

    /* Iterate through the ARP cache to check if the IP already exists */
    while (entry) {
        if (entry->ip == ip) {
            /* If entry exists, update the MAC address and timestamp */
            memcpy(entry->mac, mac, ETHER_ADDR_LEN);
            entry->added = now;  /* Update the timestamp */
            printf("Updated ARP cache entry for IP: %s\n", inet_ntoa(*(struct in_addr*)&ip));
            return;
        }
        entry = entry->next;
    }

    /* If the entry does not exist, create a new one */
    struct arp_cache_entry* new_entry = (struct arp_cache_entry*)malloc(sizeof(struct arp_cache_entry));
    new_entry->ip = ip;
    memcpy(new_entry->mac, mac, ETHER_ADDR_LEN);
    new_entry->added = now;  /* Set the current time as the timestamp */

    /* Add the new entry to the front of the ARP cache (linked list) */
    new_entry->next = arp_cache;
    arp_cache = new_entry;

    printf("Added new ARP cache entry for IP: %s\n", inet_ntoa(*(struct in_addr*)&ip));
}

/* Function to check ARP cache for an IP address and retrieve the MAC address */
int check_arp_cache(uint32_t ip, unsigned char* mac) {
    printf("Checking ARP cache for IP: %s\n", inet_ntoa(*(struct in_addr*)&ip));

    struct arp_cache_entry* entry = arp_cache;
    struct timeval now;
    if (entry){
        printf("entry ip %d\n", entry->ip);
    }

    printf("ip %d\n", ip);
    gettimeofday(&now, NULL);

    /* Iterate through the ARP cache */
    while (entry) {
        /* Check if the entry matches the IP address */
        if (entry->ip == ip) {
            /* Check if the entry is still valid (less than 10 seconds old) */
            if ((now.tv_sec - entry->added.tv_sec) <= 10) {
                memcpy(mac, entry->mac, ETHER_ADDR_LEN); /* Copy the MAC address */
                return 1; /* Cache hit */
            } else {
                /* Entry expired, remove it from cache */
                printf("ARP cache entry expired for IP: %s\n", inet_ntoa(*(struct in_addr*)&ip));
                return 0; /* Cache miss */
            }
        }
        entry = entry->next;
    }
    return 0; /* Cache miss */
}

int send_arp_request(struct sr_instance* sr, uint32_t nexthop_ip, struct sr_if* out_iface) {
    /* Create buffer for Ethernet + ARP packet */
    uint8_t buf[sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr)];
    
    /* Cast the buffer to appropriate Ethernet and ARP headers */
    struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*) buf;
    struct sr_arphdr* arp_hdr = (struct sr_arphdr*) (buf + sizeof(struct sr_ethernet_hdr));

    /* 1. Construct the Ethernet header */
    memset(e_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN); /* Destination MAC: Broadcast */
    memcpy(e_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN); /* Source MAC: Our interface's MAC */
    e_hdr->ether_type = htons(ETHERTYPE_ARP); /* EtherType: ARP */

    /* 2. Construct the ARP header */
    arp_hdr->ar_hrd = htons(ARPHRD_ETHER); /* Hardware type: Ethernet */
    arp_hdr->ar_pro = htons(ETHERTYPE_IP); /* Protocol type: IP */
    arp_hdr->ar_hln = ETHER_ADDR_LEN;      /* Hardware address length: 6 bytes */
    arp_hdr->ar_pln = 4;                   /* Protocol address length: 4 bytes */
    arp_hdr->ar_op = htons(ARPOP_REQUEST); /* Opcode: ARP request */
    
    /* Fill in sender MAC and IP addresses */
    memcpy(arp_hdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN); /* Sender hardware address: Our interface's MAC */
    arp_hdr->ar_sip = out_iface->ip; /* Sender IP address: Our interface's IP */

    /* Fill in target MAC (unknown) and IP addresses */
    memset(arp_hdr->ar_tha, 0x00, ETHER_ADDR_LEN); /* Target hardware address: Unknown, set to zero */
    arp_hdr->ar_tip = nexthop_ip; /* Target IP address: Next hop IP address */

    /* 3. Send the ARP request */
    if (sr_send_packet(sr, buf, sizeof(buf), out_iface->name) != 0) {
        fprintf(stderr, "Error: Failed to send ARP request.\n");
        return -1;
    }

    printf("Sent ARP request for IP: %s\n", inet_ntoa(*(struct in_addr*)&nexthop_ip));

    /* Now we can return the MAC address from the ARP reply */
    return 0; /* Success */
}

void sr_print_arp_cache() {
    struct arp_cache_entry* entry = arp_cache;  // Start from the head of the ARP cache linked list

    if (entry == NULL) {
        printf(" *warning* ARP cache is empty\n");
        return;
    }

    printf("IP Address\t\tMAC Address\t\tTime Added\n");

    while (entry) {
        sr_print_arp_entry(entry);
        entry = entry->next;  // Move to the next entry in the cache
    }
}

void sr_print_arp_entry(struct arp_cache_entry* entry) {
    assert(entry);

    /* Print IP Address */
    printf("%s\t", inet_ntoa(*(struct in_addr*)&entry->ip));

    /* Print MAC Address */
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", entry->mac[i]);
        if (i < ETHER_ADDR_LEN - 1) {
            printf(":");
        }
    }
    printf("\t");

    /* Print Time Added */
    printf("%ld seconds since epoch\n", entry->added.tv_sec);
}

void queue_pkt(uint8_t *packet, unsigned int len, char *iface, uint32_t next_hop_ip) {
    /* Allocate memory for a new packet in the queue */
    struct sr_packet *new_packet = (struct sr_packet *)malloc(sizeof(struct sr_packet));

    /* Copy the packet buffer */
    new_packet->buf = (uint8_t *)malloc(len);
    memcpy(new_packet->buf, packet, len);

    /* Store the packet metadata */
    new_packet->len = len;
    strncpy(new_packet->iface, iface, SR_IFACE_NAMELEN);
    new_packet->next_hop_ip = next_hop_ip;

    /* Add the packet to the front of the queue */
    new_packet->next = packet_queue;
    packet_queue = new_packet;

    printf("Queued packet waiting for ARP reply for IP: %s\n", inet_ntoa(*(struct in_addr*)&next_hop_ip));
}

void send_queued_pkts(struct sr_instance *sr, uint32_t ip, unsigned char *mac) {
    struct sr_packet *prev = NULL;
    struct sr_packet *current = packet_queue;

    while (current) {
        /* If the packet's next hop IP matches the IP from the ARP reply */
        if (current->next_hop_ip == ip) {
            printf("Sending queued packet for IP: %s\n", inet_ntoa(*(struct in_addr*)&ip));

            /* Modify the Ethernet header with the resolved MAC address */
            struct sr_ethernet_hdr *e_hdr = (struct sr_ethernet_hdr *)current->buf;
            struct sr_if *iface = sr_get_interface(sr, current->iface);
            memcpy(e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);  /* Source MAC */
            memcpy(e_hdr->ether_dhost, mac, ETHER_ADDR_LEN);          /* Destination MAC */

            /* Send the packet */
            sr_send_packet(sr, current->buf, current->len, current->iface);

            /* Remove the packet from the queue */
            if (prev) {
                prev->next = current->next;
            } else {
                packet_queue = current->next;
            }

            /* Free the memory allocated for the packet */
            free(current->buf);
            struct sr_packet *temp = current;
            current = current->next;
            free(temp);
        } else {
            prev = current;
            current = current->next;
        }
    }
}

/* Function to check if the packet's destination IP is one of the router's interfaces */
int to_myself(struct sr_instance* sr, uint32_t ip) {
    struct sr_if* iface = sr->if_list;
    while (iface) {
        if (iface->ip == ip) {
            return 1;  // Return the matching interface
        }
        iface = iface->next;
    }
    return 0;  // Packet is not for this router
}


