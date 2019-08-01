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
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    pthread_create(&thread, NULL, &handle_inbound_syn, sr);
    /* Add initialization code here! */

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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t *ip_hdr = NULL;
  int errcode;

  switch(ntohs(ethernet_hdr->ether_type))
  {
    case ethertype_arp:
      hanle_arp(sr, packet, len);
      break;
    case ethertype_ip:
      if(!is_valid_packet(packet, len)) return;
      ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
      ip_hdr->ip_ttl -= 1;
      if(ip_hdr->ip_ttl == 0)
      {
        create_and_send_icmp(sr, packet, interface, 11, 0);
        return;
      }
      switch(ip_hdr->ip_p)
      {
        case ip_protocol_icmp:
          errcode = rewrite_icmp_packet(sr, packet, len, interface);
          if(errcode == 0) return;
          break;
        case ip_protocol_tcp:
          if(strcmp(interface, "eth1") == 0)
          {
            errcode = rewrite_tcp_packet_go_out(sr, packet, len);
            if(errcode == 0) return;
          }
          else if(ip_hdr->ip_dst == htonl(IP_EXT_NAT))
          {
            errcode = rewrite_tcp_packet_come_in(sr, packet, len);
            if(errcode == 0) return;
          }
          break;
      }
      if(strcmp(interface, "eth1") == 0)
        ip_hdr->ip_src = htonl(IP_EXT_NAT);
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
      handle_forwarding(sr, packet, len);
      break;
  }
}

/* end sr_ForwardPacket */
int is_valid_packet(uint8_t *packet, unsigned int len)
{
  if(len >= ETHERNET_IP_HDR_SIZE)
  {
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    uint16_t cksum_temp = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum (packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
    if(ip_hdr->ip_sum == cksum_temp) 
      return 1;
  }
  return 0;
}

struct sr_rt *find_longest_prefix_match(struct sr_rt* routing_table, uint32_t ip)
{
  struct sr_rt *entry_rt = routing_table;
  struct sr_rt *matching_entry = NULL;
  ip = ntohl(ip);
  int snm_max = 0;
  while(entry_rt)
  {
    uint32_t snmask = ntohl((entry_rt->mask).s_addr);
    uint32_t res = ip & snmask;                               
    if((res ^ ntohl((entry_rt->dest).s_addr)) == 0 && snmask > snm_max)
    {
      matching_entry = entry_rt;
      snm_max = snmask;
    }
    entry_rt = entry_rt->next;
  }
  if(matching_entry == NULL)
  {
    entry_rt = routing_table;
    while(entry_rt != NULL && ntohl((entry_rt->mask).s_addr))
      entry_rt = entry_rt->next;
    return entry_rt;
  }
  return matching_entry;
}

struct sr_if *find_if_with_mac(struct sr_if *if_list, uint8_t mac_addr[])
{
  struct sr_if *if_rt = if_list;
  while(if_rt)
  {
    if(bcmp(if_rt->addr, mac_addr, ETHER_ADDR_LEN) == 0) 
      return if_rt;
    if_rt = if_rt->next;
  }
  return NULL;
}

struct sr_if *find_if_with_ip(struct sr_if *if_list, uint32_t ip)
{
  struct sr_if *if_rt = if_list;
  while(if_rt)
  {
    if(if_rt->ip == ip) return if_rt;
    if_rt = if_rt->next;
  }
  return NULL;
}

uint8_t* create_arp_reply(uint8_t *arp_frame, uint8_t src_mac[])
{
  /*Change ethernet header*/
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t*)arp_frame;
  memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(ethernet_hdr->ether_shost, src_mac, ETHER_ADDR_LEN);
  /*Change ARP header*/
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t*)(arp_frame + sizeof(sr_ethernet_hdr_t));
  arp_hdr->ar_op = htons(arp_op_reply);                                          
  memcpy(arp_hdr->ar_sha, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);      
  memcpy(arp_hdr->ar_tha, ethernet_hdr->ether_dhost, ETHER_ADDR_LEN); 
  uint32_t ip_temp = arp_hdr->ar_sip;
  arp_hdr->ar_sip = arp_hdr->ar_tip;                                      
  arp_hdr->ar_tip = ip_temp;                                         
  return arp_frame;
}

void create_and_send_icmp(struct sr_instance* sr, uint8_t * packet, char* interface, uint8_t icmp_type, uint8_t icmp_code)
{
  uint8_t* new_packet = calloc(ICMP_TOTAL_SIZE, 1);
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t*)new_packet;
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(new_packet + ETHERNET_IP_HDR_SIZE);
  memcpy(new_packet, packet, ETHERNET_IP_HDR_SIZE);
  memcpy((uint8_t*)icmp_hdr + sizeof(sr_icmp_hdr_t) + 4, packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t) + 8);
  memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
  ip_hdr->ip_dst = ip_hdr->ip_src;
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_len = htons(56);
  ip_hdr->ip_id = 0;
  ip_hdr->ip_p = ip_protocol_icmp;
  icmp_hdr->icmp_type = icmp_type;
  icmp_hdr->icmp_code = icmp_code;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t) + sizeof(sr_ip_hdr_t) + 12);
  struct sr_if *match_if = find_if_with_name(sr->if_list, interface);
  memcpy(ethernet_hdr->ether_shost, match_if->addr, ETHER_ADDR_LEN);
  ip_hdr->ip_src = match_if->ip;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  sr_send_packet(sr, new_packet, ICMP_TOTAL_SIZE, match_if->name);      
}

void handle_arp_request(struct sr_instance* sr, uint8_t* packet, unsigned int len)
{
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *if_rt = find_if_with_ip(sr->if_list, arp_hdr->ar_tip);
  if(if_rt != NULL)
  {
    uint8_t *arp_reply = create_arp_reply(packet, if_rt->addr);
    sr_send_packet(sr, arp_reply, len, if_rt->name);
  }
}

void handle_arp_reply(struct sr_instance* sr, uint8_t* packet, unsigned int len)
{
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t*)packet;
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_arpreq * arp_rep = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
  if(arp_rep)
  {
    struct sr_packet* packet = arp_rep->packets;
    while(packet)
    {
      uint8_t *buf = packet->buf;
      sr_ethernet_hdr_t *new_ethernet_hdr = (sr_ethernet_hdr_t*)buf;
      memcpy(new_ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
      memcpy(new_ethernet_hdr->ether_shost, ethernet_hdr->ether_dhost, ETHER_ADDR_LEN);
      sr_send_packet(sr, buf, packet->len, packet->iface);
      packet = packet->next;
    }
    sr_arpreq_destroy(&(sr->cache), arp_rep);
  }
}

void hanle_arp(struct sr_instance* sr, uint8_t* packet, unsigned int len)
{
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t*)packet;
  struct sr_if *match_if = find_if_with_mac(sr->if_list, ethernet_hdr->ether_dhost);
  if(match_if == NULL)
    handle_arp_request(sr, packet, len);
  else 
    handle_arp_reply(sr, packet, len);
}

void handle_forwarding(struct sr_instance* sr, uint8_t* packet, unsigned int len)
{
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  
  struct sr_rt *entry_rt = find_longest_prefix_match(sr->routing_table, ip_hdr->ip_dst);
  if(entry_rt == NULL)
  {
    entry_rt = find_longest_prefix_match(sr->routing_table, ip_hdr->ip_src);
    create_and_send_icmp(sr, packet, entry_rt->interface, 3, 0);
    return;
  } 
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), (entry_rt->gw).s_addr);
  if(arp_entry)
  {
    struct sr_if *match_if = find_if_with_name(sr->if_list, entry_rt->interface);
    memcpy(ethernet_hdr->ether_shost, match_if->addr, ETHER_ADDR_LEN);
    memcpy(ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, entry_rt->interface);
    free(arp_entry);
  }
  else
  {
    struct sr_arpreq *req =  sr_arpcache_queuereq(&sr->cache, (entry_rt->gw).s_addr, packet, len, entry_rt->interface);
    handle_arpreq(sr, req);
  }
}

void handle_icmp_request(struct sr_instance* sr, uint8_t* packet, unsigned int len)
{
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));

  uint16_t cksum_temp = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, len - ETHERNET_IP_HDR_SIZE);
  if(cksum_temp != icmp_hdr->icmp_sum) return;
  icmp_hdr->icmp_type = 0;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, len - ETHERNET_IP_HDR_SIZE);

  ip_hdr->ip_ttl = 64;
  uint32_t ip_temp = ip_hdr->ip_src;
  ip_hdr->ip_src = ip_hdr->ip_dst;
  ip_hdr->ip_dst = ip_temp;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  struct sr_rt *entry_rt = find_longest_prefix_match(sr->routing_table, ip_hdr->ip_dst);
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), (entry_rt->gw).s_addr);
  if(arp_entry)
  {
    struct sr_if *match_if = find_if_with_name(sr->if_list, entry_rt->interface);
    memcpy(ethernet_hdr->ether_shost, match_if->addr, ETHER_ADDR_LEN);
    memcpy(ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, entry_rt->interface);
  }
  else
  {
    struct sr_arpreq *req =  sr_arpcache_queuereq(&sr->cache, (entry_rt->gw).s_addr, packet, len, entry_rt->interface);
    handle_arpreq(sr, req);
  }
}

int rewrite_icmp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface)
{
  uint16_t temp_cksum = 0;
  sr_nat_mapping_t *mapping = NULL;

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));
  temp_cksum = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, len - ETHERNET_IP_HDR_SIZE);
  if(icmp_hdr->icmp_sum != temp_cksum) return 0;
        
  if( icmp_hdr->icmp_type == 0 || icmp_hdr->icmp_type == 8 ) 
  {
    sr_icmp_t0_hdr_t *icmp_hdr_t0 = (sr_icmp_t0_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));
    switch(icmp_hdr->icmp_type)
    {
      case 0:
        if(ip_hdr->ip_dst == htonl(IP_EXT_NAT))
        {
          mapping = sr_nat_lookup_external(&(sr->nat_icmp), icmp_hdr_t0->icmp_id, nat_mapping_icmp);
          if(mapping == NULL)
            return 0;
          icmp_hdr_t0->icmp_id = mapping->aux_int;
          ip_hdr->ip_dst = mapping->ip_int;
        }
        break;
        case 8:
          if(find_if_with_ip(sr->if_list, ip_hdr->ip_dst))
          {
            handle_icmp_request(sr, packet, len);
            return 0;
          }
          if(strcmp(interface, "eth1") == 0)
          {
            mapping = sr_nat_lookup_internal(&(sr->nat_icmp), ip_hdr->ip_src, icmp_hdr_t0->icmp_id, nat_mapping_icmp);
            if(mapping == NULL)
            {
              mapping = sr_nat_insert_mapping(&(sr->nat_icmp), ip_hdr->ip_src, icmp_hdr_t0->icmp_id, nat_mapping_icmp);
              mapping->conns = NULL;
            }
            icmp_hdr_t0->icmp_id = mapping->aux_ext;
          }
          break;
    }
  }
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, len - ETHERNET_IP_HDR_SIZE);
  return 1;
}

int rewrite_tcp_packet_go_out(struct sr_instance* sr, uint8_t* packet, unsigned int len)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));

  sr_nat_mapping_t *mapping = sr_nat_lookup_internal(&(sr->nat_tcp), ip_hdr->ip_src, tcp_hdr->tcp_src_port, nat_mapping_tcp);
  if(mapping == NULL)
  {
    if(tcp_hdr->tcp_flags & TCP_SYN)
      mapping = sr_nat_insert_mapping(&(sr->nat_tcp), ip_hdr->ip_src, tcp_hdr->tcp_src_port, nat_mapping_tcp);
    else 
      return 0;
  }
  tcp_hdr->tcp_src_port = mapping->aux_ext;
  if(tcp_hdr->tcp_flags & TCP_SYN)
  {
    sr_nat_connection_t *conn = mapping->conns;
    while(conn)
    {
      if(conn->ip_dst == ip_hdr->ip_dst && conn->port_dst == tcp_hdr->tcp_dst_port)
        break;
      conn = conn->next;
    }
    if(conn)
    {
      time(&(conn->last_time));
      return 0;
    } 
    conn = calloc(sizeof(sr_nat_connection_t), 1);
    conn->state = TRANSITORY_TCP;
    time(&(conn->last_time));
    conn->ip_dst = ip_hdr->ip_dst;
    conn->port_dst = tcp_hdr->tcp_dst_port;
    conn->next = mapping->conns;
    mapping->conns = conn;
  }
  else 
  {
    sr_nat_connection_t *conn = mapping->conns;
    while(conn)
    {
      if(conn->ip_dst == ip_hdr->ip_dst && conn->port_dst == tcp_hdr->tcp_dst_port)
        break;
      conn = conn->next;
    }
    if(conn)
    {
      if(tcp_hdr->tcp_flags & TCP_FIN)
        conn->state = TRANSITORY_TCP;
      time(&(conn->last_time));
    }
   else 
      return 0;
  }
  return 1;
}

int rewrite_tcp_packet_come_in(struct sr_instance* sr, uint8_t* packet, unsigned int len)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));

  sr_nat_mapping_t *mapping = sr_nat_lookup_external(&(sr->nat_tcp), tcp_hdr->tcp_dst_port, nat_mapping_tcp);
  if(mapping == NULL)
  {
    if(tcp_hdr->tcp_flags & TCP_SYN)
    {
      inbound_syn_t *new_syn = calloc(sizeof(inbound_syn_t), 1);
      new_syn->packet = packet;
      new_syn->aux_ext = tcp_hdr->tcp_dst_port;
      strcpy(new_syn->interface, "eth2");
      time(&(new_syn->received_time));
      new_syn->next = sr->inbound_syn_list;
      sr->inbound_syn_list = new_syn;
    }
    return 0;
  }
  sr_nat_connection_t *conn = mapping->conns;
  while(conn)
  {
    if(conn->ip_dst == ip_hdr->ip_src && conn->port_dst == tcp_hdr->tcp_src_port)
      break;
    conn = conn->next;
  }
  if(conn)
  {
    if( (tcp_hdr->tcp_flags & TCP_SYN) && (tcp_hdr->tcp_flags & TCP_ACK) )
      conn->state = ESTABLISHED_TCP;
    if(tcp_hdr->tcp_flags & TCP_FIN)
      conn->state = TRANSITORY_TCP;
    time(&(conn->last_time));
  }
  else 
    return 0;
  tcp_hdr->tcp_dst_port = mapping->aux_int;
  ip_hdr->ip_dst = mapping->ip_int;
  return 1;
}

void* handle_inbound_syn(void *arg)
{
  pthread_detach(pthread_self());
  struct sr_instance* sr = (struct sr_instance*)arg;
  uint8_t* packet = NULL;
  inbound_syn_t *syn_seg = NULL;
  inbound_syn_t *syn_seg_prev = NULL;
  inbound_syn_t *temp_syn = NULL;
  while(1)
  {
    syn_seg = sr->inbound_syn_list;
    syn_seg_prev = NULL;
    while(syn_seg)
    {
      packet = syn_seg->packet;
      if(time(NULL) - syn_seg->received_time < 6)
      {
        if(sr_nat_lookup_external(&(sr->nat_tcp), syn_seg->aux_ext, nat_mapping_tcp) != NULL)
        {
          temp_syn = syn_seg->next;
          if(syn_seg_prev) 
            syn_seg_prev->next = syn_seg->next;
          else 
            sr->inbound_syn_list = syn_seg->next;
          free(syn_seg);
          syn_seg = temp_syn;
          continue;
        }
      }
      else 
      {
        create_and_send_icmp(sr, packet, syn_seg->interface, 3, 3);
        temp_syn = syn_seg->next;
        if(syn_seg_prev) 
          syn_seg_prev->next = syn_seg->next;
        else 
          sr->inbound_syn_list = syn_seg->next;
        free(syn_seg);
        syn_seg = temp_syn;
        continue;
      }
      syn_seg_prev = syn_seg;
      syn_seg = syn_seg->next;
    }
  }
  return NULL;
}