/******************************************************************************
 * ctcp.c
 * ------
 * Implementation of cTCP done here. This is the only file you need to change.
 * Look at the following files for references and useful functions:
 *   - ctcp.h: Headers for this file.
 *   - ctcp_iinked_list.h: Linked list functions for managing a linked list.
 *   - ctcp_sys.h: Connection-related structs and functions, cTCP segment
 *                 definition.
 *   - ctcp_utils.h: Checksum computation, getting the current time.
 *
 *****************************************************************************/

#include "ctcp.h"
#include "ctcp_linked_list.h"
#include "ctcp_sys.h"
#include "ctcp_utils.h"

/**
 * Connection state.
 *
 * Stores per-connection information such as the current sequence number,
 * unacknowledged packets, etc.
 *
 * You should add to this to store other fields you might need.
 */
#define WAITING_INPUT 0x01
#define WAITING_ACK 0x02
#define RECVED_EOF 0x04
#define RECVED_FIN 0x08
#define SENT_FIN 0x10
#define FINISHED_OUTPUT 0x20 
#define TIME_WAIT 8000

struct ctcp_state {
  struct ctcp_state *next;  /* Next in linked list */
  struct ctcp_state **prev; /* Prev in linked list */

  conn_t *conn;             /* Connection object -- needed in order to figure
                               out destination when sending */
  linked_list_t *sent_segments;  /* Linked list of segments sent to this connection.
                               It may be useful to have multiple linked lists
                               for unacknowledged segments, segments that
                               haven't been sent, etc. Lab 1 uses the
                               stop-and-wait protocol and therefore does not
                               necessarily need a linked list. You may remove
                               this if this is the case for you */
  linked_list_t *recved_segments;
  uint32_t seqno;
  uint32_t ackno;
  uint32_t numSent;
  uint32_t numRecved;
  uint32_t posOutput;
  uint16_t status;
  uint32_t timeout;
  uint16_t send_window;
  uint16_t recv_window;
  long timer_destroy;
  char recv_buffer[MAX_SEG_DATA_SIZE];
};

typedef struct 
{
  ctcp_segment_t *seg;
  long lastTransmitTime;
  uint16_t num_retransmit;
} ctcp_segment_to;
/**
 * Linked list of connection states. Go through this in ctcp_timer() to
 * resubmit segments and tear down connections.
 */
static ctcp_state_t *state_list;

/* FIXME: Feel free to add as many helper functions as needed. Don't repeat
          code! Helper functions make the code clearer and cleaner. */

void create_segment_and_send(ctcp_state_t *state, uint32_t flags, char* data, uint32_t len);
void process_data_segment (ctcp_state_t *state, ctcp_segment_t *segment);
void process_ack_segment (ctcp_state_t *state, ctcp_segment_t *segment);
void process_fin_segment (ctcp_state_t *state, ctcp_segment_t *segment);

ctcp_state_t *ctcp_init(conn_t *conn, ctcp_config_t *cfg) {
  /* Connection could not be established. */
  if (conn == NULL) {
    return NULL;
  }

  /* Established a connection. Create a new state and update the linked list
     of connection states. */
  ctcp_state_t *state = calloc(sizeof(ctcp_state_t), 1);
  state->next = state_list;
  state->prev = &state_list;
  if (state_list)
    state_list->prev = &state->next;
  state_list = state;

  /* Set fields. */
  state->conn = conn;
  state->seqno = state->ackno = 1;
  state->numSent = state->numRecved = 0;
  state->posOutput = 0;
  state->timeout = cfg->rt_timeout;
  state->recv_window = cfg->recv_window;
  state->send_window = cfg->send_window;
  state->status |= (WAITING_INPUT | FINISHED_OUTPUT);
  state->sent_segments = ll_create();
  state->recved_segments = ll_create();
  state->timer_destroy = 0;
  free(cfg);
  return state;
}

void ctcp_destroy(ctcp_state_t *state) {
  /* Update linked list. */
  if (state->next)
    state->next->prev = state->prev;

  *state->prev = state->next;
  conn_remove(state->conn);

  free(state);
  end_client();
}

void ctcp_read(ctcp_state_t *state) {
  if(state->status & WAITING_INPUT)
  {
    char buffer[MAX_SEG_DATA_SIZE];
    int bytesLeft = state->send_window - state->numSent;
    int n = conn_input(state->conn, buffer, bytesLeft < MAX_SEG_DATA_SIZE ? bytesLeft : MAX_SEG_DATA_SIZE);
    if(n == 0) return;
    ctcp_state_t *curr_state = state_list;
    ctcp_state_t *temp_state = NULL;
    if (n == -1)
    {
      while(curr_state)
      {
        temp_state = curr_state->next;
        curr_state->status &= ~WAITING_INPUT;
        curr_state->status |= (SENT_FIN | RECVED_EOF | WAITING_ACK);
        create_segment_and_send(curr_state, FIN, NULL, 0);
        curr_state = temp_state;
      }
    }
    else
    {
      while(curr_state)
      {
        create_segment_and_send(curr_state, ACK, buffer, n);
        curr_state->numSent += n;
        curr_state->seqno += n;
        if(curr_state->numSent == curr_state->send_window)
        {
          curr_state->status &= ~WAITING_INPUT;
        }
        curr_state->status |= WAITING_ACK;
        curr_state = curr_state->next;
      }
    }
  }
}

void ctcp_receive(ctcp_state_t *state, ctcp_segment_t *segment, size_t len) {
  if(len < ntohs(segment->len))
  {
    free(segment);
    return;
  }
  uint16_t segmentChecksum = segment->cksum;
  segment->cksum = 0;
  uint16_t computedChecksum = cksum(segment, ntohs(segment->len));
  if(computedChecksum != segmentChecksum) 
  {
    free(segment);
    return;
  }
  uint32_t flags = segment->flags;
  if (ntohs(segment->len) > sizeof(ctcp_segment_t))
  {
    process_data_segment(state, segment);
    if (flags & TH_ACK)
     process_ack_segment(state, segment);
  }
  else
  {
    if (flags & TH_ACK)
      process_ack_segment(state, segment);
    else if (flags & TH_FIN) 
      process_fin_segment(state, segment);
  }
  free(segment);
}

void ctcp_output(ctcp_state_t *state) {
  uint32_t freeSpace;
  if((freeSpace = conn_bufspace(state->conn)) == 0) return;
  uint32_t leftData = state->numRecved - state->posOutput;
  uint32_t min = freeSpace < leftData ? freeSpace : leftData;
  uint32_t written = conn_output(state->conn, (char*)state->recv_buffer + state->posOutput, min);
  state->posOutput += written;
  if(state->posOutput == state->numRecved) 
  {
    state->status |= FINISHED_OUTPUT;
    state->posOutput = 0;
  }
}

void ctcp_timer() {
  ctcp_state_t * state = state_list;
  ctcp_state_t * temp_state = NULL;
  ll_node_t *curr_node = NULL;
  ctcp_segment_to *curr_segment = NULL;
  while(state)
  { 
    temp_state = state->next;
    if((state->status == (FINISHED_OUTPUT | RECVED_EOF | RECVED_FIN | SENT_FIN)))
    {
      conn_output(state->conn, NULL, 0);
      if(state->timer_destroy == 0) state->timer_destroy = current_time();
      if((current_time() - state->timer_destroy) >= TIME_WAIT)
        ctcp_destroy(state);
    }
    else if(state->status & WAITING_ACK)
    {
      curr_node = state->sent_segments->head; 
      while(curr_node)
      {
        curr_segment = curr_node->object;
        if(current_time() - curr_segment->lastTransmitTime >= state->timeout)
        {
          if(curr_segment->num_retransmit > 5)
          {
            ctcp_destroy(state);
            break;
          }
          curr_segment->num_retransmit++;
          conn_send(state->conn, curr_segment->seg, ntohs(curr_segment->seg->len));
          curr_segment->lastTransmitTime = current_time();
        }
        curr_node = curr_node->next;
      }
    }
    state = temp_state;
  }
}

void create_segment_and_send(ctcp_state_t *state, uint32_t flags, char* data, uint32_t len)
{
  ctcp_segment_to *ctcp_seg = NULL;
  ctcp_seg = calloc(sizeof(ctcp_segment_to), 1);
  uint32_t segment_len = len + sizeof(ctcp_segment_t);
  ctcp_seg->seg = calloc(segment_len, 1);
  ctcp_seg->seg->flags = htonl(flags);
  ctcp_seg->seg->seqno = htonl(state->seqno);
  ctcp_seg->seg->ackno = htonl(state->ackno);
  ctcp_seg->seg->len = htons(segment_len);
  ctcp_seg->seg->window = htons(state->send_window);
  ctcp_seg->seg->cksum = 0;
  
  if(len > 0) 
    memcpy(ctcp_seg->seg->data, data, len);
  ctcp_seg->seg->cksum = cksum(ctcp_seg->seg, segment_len);
  ctcp_seg->num_retransmit = 0;
  conn_send(state->conn, ctcp_seg->seg, segment_len);
  if(len > 0 || flags & FIN) 
  {
    ctcp_seg->lastTransmitTime = current_time();
    ll_add(state->sent_segments, ctcp_seg);
  }
}

void process_data_segment (ctcp_state_t *state, ctcp_segment_t *segment)
{
  int seqno = ntohl(segment->seqno);
  int data_length = ntohs(segment->len) - sizeof(ctcp_segment_t);
  int temp_ackno = state->ackno;
  state->ackno = seqno + data_length;
  create_segment_and_send(state, ACK, NULL, 0);
  if(state->ackno <= temp_ackno)
  {
    state->ackno = temp_ackno;
    return;
  } 
  state->ackno = temp_ackno;
  ll_node_t *curr_node = NULL;
  ctcp_segment_t *ctcp_seg = NULL;
  ll_node_t *temp_node = NULL;
  if(ll_length(state->recved_segments) == 0)
    ll_add(state->recved_segments, segment);
  else
  {
    curr_node = state->recved_segments->head;
    while(curr_node)
    {
      ctcp_seg = (ctcp_segment_t*)curr_node->object;
      if(ntohl(ctcp_seg->seqno) >= seqno) break;
      curr_node = curr_node->next;
    }
    if(curr_node != NULL && ntohl(ctcp_seg->seqno) == seqno)
    {
        return;
    }
    if(curr_node->prev)
      ll_add_after(state->recved_segments, curr_node->prev, segment);
    else 
      ll_add_front(state->recved_segments, segment);
  }
  curr_node = state->recved_segments->head;
  while(curr_node)
  {
    ctcp_seg = curr_node->object;
    if(ntohl(ctcp_seg->seqno) == state->ackno)
    {
      state->numRecved = ntohs(segment->len) - sizeof(ctcp_segment_t);
      state->ackno += state->numRecved;
      memcpy(state->recv_buffer, segment->data, state->numRecved);
      state->posOutput = 0;
      state->status &= ~FINISHED_OUTPUT;
      ctcp_output(state);
      temp_node = curr_node->next;
      ll_remove(state->recved_segments, curr_node);
      curr_node = temp_node;
    }
    else break;
  }
}

void process_ack_segment (ctcp_state_t *state, ctcp_segment_t *segment)
{
  uint32_t ackno = ntohl(segment->ackno);
  uint32_t seqno;
  uint32_t len_t;
  ll_node_t *curr_node = state->sent_segments->head;   
  ll_node_t *temp_node = NULL;  
  ctcp_segment_to *curr_segment = NULL;
  while(curr_node)
  {
    temp_node = curr_node->next;
    curr_segment = curr_node->object;
    seqno = ntohl(curr_segment->seg->seqno);
    len_t = ntohs(curr_segment->seg->len) - sizeof(ctcp_segment_t);
    if(ackno == seqno + 1)
    {
      state->status &= ~WAITING_ACK;          
      free(ll_remove(state->sent_segments, curr_node));
    }
    else if(ackno == seqno + len_t)
    {
      if(curr_node == state->sent_segments->head)
      {
        state->status |= WAITING_INPUT;
        state->numSent -= len_t;
      } 
      free(ll_remove(state->sent_segments, curr_node));
      if(ll_length(state->sent_segments) == 0) state->status &= ~WAITING_ACK;
    }
    curr_node = temp_node;
  }
}

void process_fin_segment (ctcp_state_t *state, ctcp_segment_t *segment)
{
  uint32_t seqno = ntohl(segment->seqno);
  state->ackno =  seqno + 1;
  state->status |= (RECVED_EOF | RECVED_FIN);
  state->status &= ~WAITING_INPUT;
  create_segment_and_send(state, ACK, NULL, 0);
  if (!(state->status & SENT_FIN)){
      state->status |= (SENT_FIN | WAITING_ACK);
      create_segment_and_send(state, FIN, NULL, 0);
  }
}
