#ifndef _OBEX_LAYOUT_H_
#define _OBEX_LAYOUT_H_

#include <arpa/inet.h>
#include <stdint.h>

#include "obex_packet_def.h"
#include "obex_impl.h"

extern obex_request_t *obex_make_first_put_req(ohdr_init_collect *hdrs);
extern obex_request_t *obex_make_rest_put(ohdr_init_collect *hdrs);
extern obex_request_t *ctor_obex_connect_request(uint8_t, uint8_t,
                                                 uint16_t, size_t);

/* caller must ensures @p's size at least is 7 bytes */
static inline uint8_t *extract_obex_conn_vern(struct obex_packet *p)
{
        uint8_t *start = (uint8_t *)p;
        start += OBEX_PACKET_HDR_SIZE;
        return start;
}

static inline uint8_t *extract_obex_conn_flags(struct obex_packet *p)
{
        return extract_obex_conn_vern(p) + 1;
}

static inline uint16_t *extract_obex_conn_maxpsize(struct obex_packet *p)
{
        return (uint16_t *)(extract_obex_conn_flags(p) + 1);
}

/* caller must ensures @p's size at least is 8 bytes */
static inline void *extract_obex_conn_opt(struct obex_packet *p)
{
        return extract_obex_conn_maxpsize(p) + 1;
}

/* destructor of CONNECT packet */
#define dtor_obex_connect_request(__req) dtor_obex_packet(__req)

#define ctor_obex_minimal_disconnect_local(__name) \
        uint8_t __name##__buffer[OBEX_PACKET_HDR_SIZE] = {0}; \
        obex_request_t *__name = (obex_request_t *)__name##__buffer; \
        __name->packet_code = OBEX_REQC_DISCONNECT,                  \
                __name->packet_len_netord = htons(OBEX_PACKET_HDR_SIZE)

#define dtor_obex_minimal_disconnect_local(__name) \
        __name = NULL

/* minimal response packet */
#define ctor_obex_minimal_response_local(__name)                        \
        uint8_t __name##__buffer[OBEX_PACKET_HDR_SIZE] = {0};           \
        obex_response_t *__name = (obex_response_t *) __name##__buffer  \

/* minimal response packet destructor */
#define dtor_obex_minimal_response_local(__name)      \
        __name = NULL                                 \


#endif /* obex_layout.h */
