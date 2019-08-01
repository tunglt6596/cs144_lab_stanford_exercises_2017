
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

extern time_t icmp_id_timeout;
extern time_t tcp_established_idle_timeout;
extern time_t tcp_transitory_idle_timeout;

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

int can_be_removed(struct sr_nat *nat_ptr, struct sr_nat_mapping *mapp)
{
  sr_nat_mapping_t *mapping = NULL;
  sr_nat_connection_t *conn_cmp = NULL;
  sr_nat_connection_t *conn = mapp->conns;
  while(conn)
  {
    mapping = nat_ptr->mappings;
    while(mapping)
    {
      conn_cmp = mapping->conns;
      while(conn_cmp)
      {
        if( (conn->ip_dst == conn_cmp->ip_dst) && (conn->port_dst == conn_cmp->port_dst) ) 
          if(conn_cmp->state == ESTABLISHED_TCP)
            return 0;
        conn_cmp = conn_cmp->next;   
      }
      mapping = mapping->next;
    }
    conn = conn->next;
  }
  return 1;
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));
    time_t curtime = time(NULL);
    sr_nat_mapping_t *sr_mapping = nat->mappings;
    if( (sr_mapping) && (sr_mapping->type == nat_mapping_icmp) )
    {
      sr_nat_mapping_t *sr_mapping_prev = NULL;
      sr_nat_mapping_t *temp_mapping = NULL;
      while(sr_mapping)
      {
        if(curtime - sr_mapping->last_updated < icmp_id_timeout)
        {
          sr_mapping_prev = sr_mapping;
          sr_mapping = sr_mapping->next;
        }
        else 
        {
          if(sr_mapping_prev)
            sr_mapping_prev->next = sr_mapping->next;
          else 
            nat->mappings = sr_mapping->next;
          temp_mapping = sr_mapping->next;
          printf("Remove mapping icmp id: %d\n", ntohs(sr_mapping->aux_ext));
          free(sr_mapping);
          sr_mapping = temp_mapping;
        }
      }
    }
    else if( (sr_mapping) && (sr_mapping->type == nat_mapping_tcp) )
    {
      while(sr_mapping)
      {
        sr_nat_connection_t *conn = sr_mapping->conns;
        while(conn)
        {
          if( (conn->state & TRANSITORY_TCP) && (curtime - conn->last_time >= tcp_transitory_idle_timeout) )
            conn->state = CAN_BE_REMOVED;
          else if( (conn->state & ESTABLISHED_TCP) && (curtime - conn->last_time >= tcp_established_idle_timeout) )
            conn->state = CAN_BE_REMOVED;
          conn = conn->next;
        }
        sr_mapping = sr_mapping->next;
      }
      sr_mapping = nat->mappings;
      sr_nat_mapping_t *temp_mapping = NULL;
      sr_nat_mapping_t *sr_mapping_prev = NULL;
      while(sr_mapping)
      {
        int res = 1;
        sr_nat_connection_t *conn = sr_mapping->conns;
        while(conn)
        {
          if(conn->state != CAN_BE_REMOVED)
          {
            res = 0;
            break;
          }
          conn = conn->next;
        }
        if(res)
          res = can_be_removed(nat, sr_mapping);
        if(res)
        {
          if(sr_mapping_prev)
            sr_mapping_prev->next = sr_mapping->next;
          else 
            nat->mappings = sr_mapping->next;
          temp_mapping = sr_mapping->next;
          printf("Remove mapping tcp: %d\n", ntohs(sr_mapping->aux_ext));
          conn = sr_mapping->conns;
          sr_nat_connection_t *temp_conn = NULL;
          while(conn)
          {
            temp_conn = conn->next;
            free(conn);
            conn = temp_conn;
          }
          free(sr_mapping);
          sr_mapping = temp_mapping;
          continue;
        } 
        sr_mapping_prev = sr_mapping;
        sr_mapping = sr_mapping->next;
      }
    }
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *curr = nat->mappings;
  while(curr)
  {
    if(curr->aux_ext == aux_ext)
    {
      copy = calloc(sizeof(sr_nat_mapping_t), 1);
      memcpy(copy, curr, sizeof(sr_nat_mapping_t));
      break;
    }
    curr = curr->next;
  }
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *curr = nat->mappings;
  while(curr)
  {
    if(curr->ip_int == ip_int && curr->aux_int == aux_int)
    {
      copy = calloc(sizeof(sr_nat_mapping_t), 1);
      memcpy(copy, curr, sizeof(sr_nat_mapping_t));
      break;
    }
    curr = curr->next;
  }
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;
  mapping = (sr_nat_mapping_t*)calloc(sizeof(sr_nat_mapping_t), 1);
  mapping->type = type;
  mapping->ip_int = ip_int; /* internal ip addr */
  mapping->ip_ext = htonl(IP_EXT_NAT); /* external ip addr */
  mapping->aux_int = aux_int; /* internal port or icmp id */
  mapping->conns = NULL;
  long min;
  sr_nat_mapping_t *sr_mapping = NULL;
  sr_nat_mapping_t *sr_mapping_prev = NULL;
  if(nat->mappings)
  {
    switch(type)
    {
      case nat_mapping_icmp:
        min = -1;
        break;
      case nat_mapping_tcp:
        min = 1023;
        break;
    }
    sr_mapping = nat->mappings;
    sr_mapping_prev = NULL;
    while(sr_mapping)
    {
      if((long)ntohs(sr_mapping->aux_ext) - min > 1)
      {
        mapping->aux_ext = htons(min + 1);
        break;
      }
      min = ntohs(sr_mapping->aux_ext);
      sr_mapping_prev = sr_mapping;
      sr_mapping = sr_mapping->next;
    }
    if(sr_mapping == NULL)
    {
      mapping->aux_ext = htons(min + 1);
      mapping->next = NULL;
      sr_mapping_prev->next = mapping;
    }
    else if(sr_mapping_prev)
    {
      mapping->next = sr_mapping_prev->next;
      sr_mapping_prev->next = mapping;
    }
    else 
    {
      mapping->next = sr_mapping;
      nat->mappings = mapping;
    }
  }
  else
  {
    switch(type)
    {
      case nat_mapping_icmp:
        mapping->aux_ext = htons(0);
        break;
      case nat_mapping_tcp:
        mapping->aux_ext = htons(1024);
        break;
    }
    mapping->next = NULL;
    nat->mappings = mapping;
  }
  time(&(mapping->last_updated)); /* use to timeout mappings */ 
  printf("New mapping: %d\n", ntohs(mapping->aux_ext));
  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}
