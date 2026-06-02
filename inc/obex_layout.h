#ifndef _OBEX_LAYOUT_H_
#define _OBEX_LAYOUT_H_

#include <arpa/inet.h>
#include <stdint.h>

#include "obex_packet_def.h"
#include "obex_impl.h"

struct obex_layout_operations;
/**
 * obex_layout_struct - structure used to represents obex packet layout.
 * @p:                  inner buffer
 * @packet_size:        inner buffer size
 * @p_get:              is @p acquired by other
 * @allocated:          is @p valid
 * @refcnt:             ref count
 */
struct obex_layout_struct {
        struct obex_packet *p;
        size_t packet_size;
        int p_get;
        int allocated;
        int refcnt;
        const struct obex_layout_operations *lops;
};

struct obex_layout_operations {
        const struct obex_packet *(*get_packet)(struct obex_layout_struct *handle);
        struct obex_packet *(*get_packet_mutable)(struct obex_layout_struct *handle);
        void (*put_packet)(struct obex_layout_struct *handle);
        int (*make_packet)(struct obex_layout_struct *handle, uint8_t code, ohdr_init_collect *);
        int (*drop_packet)(struct obex_layout_struct *handle);
        const struct obex_layout_operations *(*replace_ops)(struct obex_layout_struct *handle,
                                                     struct obex_layout_operations *new);
};

/*
        int (*mini_put)(struct obex_layout_struct *handle, const char *name,
                     const char *type, size_t length, void *chunk,
                     size_t chunk_size, int all);
*/

/* ctor and dtor */
extern struct obex_layout_struct *ctor_obex_layout(void);
static inline void dtor_obex_layout(struct obex_layout_struct *handle)
{
        if (handle->allocated)
                free(handle->p);
        free(handle);
}

static inline void get_layout(struct obex_layout_struct *layout)
{
        layout->refcnt++;
}

static inline void put_layout(struct obex_layout_struct *layout)
{
        layout->refcnt--;
        if (!layout->refcnt) {
                dtor_obex_layout(layout);
        }
}

/* friend function */
static inline bool obex_layout_is_inuse(struct obex_layout_struct *handle)
{
        return handle->refcnt > 0;
}

static inline bool obex_layout_is_allocated(struct obex_layout_struct *handle)
{
        return handle->allocated;
}
extern void copy_obex_mini_connect(uint8_t, uint16_t, void *, uint8_t);
extern const uint8_t obex_mini_eob_req[OBEX_PACKET_HDR_SIZE + OBEX_PACKET_HDR_SIZE];

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

static inline uint8_t *obex_connect_vern(obex_request_t *connect_req)
{
        return (uint8_t *)((uint8_t *)connect_req + OBEX_CONNECT_VERN_OFFSET);
}

static inline uint8_t *obex_connect_flags(obex_request_t *connect_req)
{
        return (uint8_t *)((uint8_t *)connect_req + OBEX_CONNECT_FLAGS_OFFSET);
}

static inline uint16_t *obex_connect_mpsize(obex_request_t *connect_req)
{
        return (uint16_t *)((uint8_t *)connect_req + OBEX_CONNECT_MPSIZE_OFFSET);
}

static inline void *obex_connect_opt(obex_request_t *connect_req)
{
        return (uint8_t *)connect_req + OBEX_CONNECT_OPT_OFFSET;
}


#endif /* obex_layout.h */
