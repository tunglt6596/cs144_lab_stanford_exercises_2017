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

#define WAITING_ACK 0x01
#define RECVED_EOF 0x02
#define RECVED_FIN 0x04
#define SENT_FIN 0x08
#define FINISHED_OUTPUT 0x10 
#define TIME_WAIT 8000

struct ctcp_state {
  struct ctcp_state *next;  /* Next in linked list */
  struct ctcp_state **prev; /* Prev in linked list */

  conn_t *conn;             /* Connection object -- needed in order to figure
                               out destination when sending */
  ctcp_segment_t *sent_segment;  
  
  uint32_t seqno;
  uint32_t ackno;
  uint32_t numRecved;
  uint32_t posOutput;
  uint32_t retransmitCount;
  long lastTransmitTime;
  uint16_t status;
  char recv_buffer[MAX_SEG_DATA_SIZE];
  uint32_t timeout;
  uint16_t send_window;
  long timer_destroy;
};
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

  state->conn = conn;
  state->seqno = state->ackno = 1;
  state->numRecved = 0;
  state->posOutput = 0;
  state->timeout = cfg->rt_timeout;
  state->send_window = cfg->send_window;
  state->retransmitCount = 0;
  state->lastTransmitTime = 0;
  state->status = FINISHED_OUTPUT;
  state->timer_destroy = 0;
  state->sent_segment = calloc(sizeof(ctcp_segment_t) + MAX_SEG_DATA_SIZE, 1);
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
  if(!(state->status & WAITING_ACK))
  {
    char buffer[MAX_SEG_DATA_SIZE];
    memset(buffer, 0, MAX_SEG_DATA_SIZE);
    int n = conn_input(state->conn, buffer, MAX_SEG_DATA_SIZE);
    if(n == 0) return;
    ctcp_state_t *curr_state = state_list;
    ctcp_state_t *temp_state = NULL;
    if (n == -1)
    {
      while(curr_state)
      {
        curr_state->status |= (SENT_FIN | RECVED_EOF | WAITING_ACK);
        temp_state = curr_state->next;
        create_segment_and_send(curr_state, FIN, NULL, 0);
        curr_state = temp_state;
      }
    }
    else
    {
      while(curr_state)
      {
        create_segment_and_send(curr_state, ACK, buffer, n);
        curr_state->seqno += n;
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
    state->status &= ~FINISHED_OUTPUT;
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
    else if (state->status & WAITING_ACK)
    {
      if((current_time() - state->lastTransmitTime) >= state->timeout)
      {
        if(state->retransmitCount > 5)
        {
            ctcp_destroy(state);
        }
        else 
	      {
	        state->retransmitCount++;
          conn_send(state->conn, state->sent_segment, htons(state->sent_segment->len));
	        state->lastTransmitTime = current_time();
        }
      }
    }
    state = temp_state;
  }
}

void create_segment_and_send(ctcp_state_t *state, uint32_t flags, char* data, uint32_t len)
{
  ctcp_segment_t *ctcp_seg = NULL;
  uint32_t segment_len = len + sizeof(ctcp_segment_t);
  ctcp_seg = calloc(segment_len, 1);
  ctcp_seg->flags = htonl(flags);
  ctcp_seg->seqno = htonl(state->seqno);
  ctcp_seg->ackno = htonl(state->ackno);
  ctcp_seg->len = htons(segment_len);
  ctcp_seg->window = htons(state->send_window);
  ctcp_seg->cksum = 0;
  if(len > 0) 
  	memcpy(ctcp_seg->data, data, len);
  ctcp_seg->cksum = cksum(ctcp_seg, segment_len);
  conn_send(state->conn, ctcp_seg, segment_len);
  if(len > 0 || flags & FIN)
  {
    state->lastTransmitTime = current_time();
    memcpy(state->sent_segment, ctcp_seg, segment_len);
    state->retransmitCount = 0;
  }
}

void process_data_segment (ctcp_state_t *state, ctcp_segment_t *segment)
{
  int seqno = ntohl(segment->seqno);
  if(seqno < state->ackno) //seqno of segment < state->ackno
  {
    create_segment_and_send(state, ACK, NULL, 0);
  }
  else if(seqno == state->ackno) //seqno of segment == state->ackno
  {
    state->numRecved = ntohs(segment->len) - sizeof(ctcp_segment_t);
    state->ackno += state->numRecved;
    create_segment_and_send(state, ACK, NULL, 0);
    memcpy(state->recv_buffer, segment->data, state->numRecved);
    state->posOutput = 0;
    ctcp_output(state);
  }
}

void process_ack_segment (ctcp_state_t *state, ctcp_segment_t *segment)
{
  uint32_t ackno = ntohl(segment->ackno);
  uint32_t seqno = ntohl(state->sent_segment->seqno);
  uint32_t len = ntohs(state->sent_segment->len) - sizeof(ctcp_segment_t);
  if(ackno == seqno + 1 || ackno == seqno + len)
    state->status &= ~WAITING_ACK;
}

void process_fin_segment (ctcp_state_t *state, ctcp_segment_t *segment)
{
  uint32_t seqno = ntohl(segment->seqno);
  state->ackno =  seqno + 1;
  state->status |= (RECVED_EOF | RECVED_FIN);
  create_segment_and_send(state, ACK, NULL, 0);
  if (!(state->status & SENT_FIN)){
      state->status |= (SENT_FIN | WAITING_ACK);
      create_segment_and_send(state, FIN, NULL, 0);
  }
}
