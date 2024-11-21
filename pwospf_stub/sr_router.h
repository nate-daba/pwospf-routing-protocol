/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#ifdef VNL
#include "vnlconn.h"
#endif

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

struct pwospf_subsys;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */
struct arp_cache_entry {
    uint32_t ip;                    /* IP address */
    unsigned char mac[ETHER_ADDR_LEN]; /* MAC address */
    struct timeval added;            /* Time when the entry was added */
    struct arp_cache_entry* next;    /* Pointer to the next entry */
};

struct sr_instance
{
    int  sockfd;   /* socket to server */
#ifdef VNL
    struct VnlConn* vc;
#endif
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    char auth_key_fn[64]; /* auth key filename */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    FILE* logfile;
    volatile uint8_t  hw_init; /* bool : hardware has been initialized */

    /* -- pwospf subsystem -- */
    struct pwospf_subsys* ospf_subsys;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
uint16_t checksum(void* vdata, size_t length);
int lookup_rt(struct sr_instance* sr, uint32_t dest_ip, uint32_t* nexthop, char* out_iface);
void process_arp_reply(struct sr_instance* sr, struct sr_arphdr* arp_reply);
int check_arp_cache(uint32_t ip, unsigned char* mac);
int send_arp_request(struct sr_instance* sr, uint32_t nexthop_ip, struct sr_if* out_iface);
void sr_print_arp_cache();
void sr_print_arp_entry(struct arp_cache_entry* entry);
void queue_pkt(uint8_t *packet, unsigned int len, char *iface, uint32_t next_hop_ip);
void send_queued_pkts(struct sr_instance *sr, uint32_t ip, unsigned char *mac);
void update_arp_cache(struct sr_instance* sr, uint32_t ip, unsigned char* mac);
int to_myself(struct sr_instance* sr, uint32_t ip);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
