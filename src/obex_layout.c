#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "obex_packet_def.h"
#include "obex_impl.h"
#include "obex_layout.h"

static size_t accumulate_hdrs_size(ohdr_init_collect *hdrs)
{
        size_t hdr_size = 0;
        size_t value_size = 0;
        ohdr_init_collect *entity;
        ohdr_init_collect_for_each_entry(entity, hdrs) {
                value_size = obex_hdr_probe_initializer_size(entity->hi,
                                                             &entity->value);
                hdr_size += obex_hdr_compute_size(entity->hi, value_size);
        }
        value_size = obex_hdr_probe_initializer_size(hdrs->hi, &hdrs->value);
        hdr_size += obex_hdr_compute_size(hdrs->hi, value_size);
        return hdr_size;
}

/**
 * We build the first PUT packet from initializer list.
 *
 *            ... <-> body hdr <-> hdr1 <-> hdr2 <-> hdr3 <-> ...
 *                                 /        /        /
 *                                |        /        /
 *                                |       /        /
 *                                |      |        |
 *   first put => [ code | len | -------- hdrs -------- ]
 *                                                  #^ BODY hdr
 * # we do not checks @hdrs == NULL,caller must take care of
 *   that.
 */
obex_request_t *obex_make_first_put_req(ohdr_init_collect *hdrs)
{
        size_t total_size = 0;
        ohdr_init_collect *entity = NULL;
        bool all = false;
        size_t hdr_size = accumulate_hdrs_size(hdrs);
        obex_request_t *req = ctor_obex_packet(OBEX_REQC_PUT,
                                               obex_packet_compute_size(hdr_size));
        if (!req)
                return NULL;

        void *addr_iter = req;
        /* skip packet hdr */
        addr_iter += OBEX_PACKET_HDR_SIZE;
        
        /* initialize the first header */
        addr_iter = obex_hdr_ctor_inplace(addr_iter, hdrs->hi, &hdrs->value);
        if (!addr_iter)
                goto exit_err_free;

        /* initialize the rest header(s) */
        ohdr_init_collect_for_each_entry(entity, hdrs) {
                /* we expect BODY and EOB is the last one */
                if (entity->hi == OBEX_HI_BODY || entity->hi == OBEX_HI_EOB) {
                        if (entity->list.next != &hdrs->list)
                                goto exit_err_free;
                        if (entity->hi == OBEX_HI_EOB)
                                all = true;
                }
                
                addr_iter = obex_hdr_ctor_inplace(addr_iter, entity->hi,
                                                  &entity->value);
                if (!addr_iter)
                        goto exit_err_free;
        }

        if (all)
                obex_set_final(&req->packet_code);
        return req;

exit_err_free:
        dtor_obex_packet(req);
        return NULL;
}

/**
 * similar to obex_make_first_put(),but all headers are either BODY or
 * EOB.
 */
obex_request_t *obex_make_rest_put(ohdr_init_collect *hdrs)
{
        bool all = false;
        /* we check head at first,check rest in initializing phase */
        if (hdrs->hi != OBEX_HI_BODY && hdrs->hi != OBEX_HI_EOB)
                return NULL;
        
        size_t hdr_size = accumulate_hdrs_size(hdrs);
        obex_request_t *req = ctor_obex_packet(OBEX_REQC_PUT,
                                               obex_packet_compute_size(hdr_size));
        if (!req)
                return NULL;

        void *addr_iter = req;
        addr_iter += OBEX_PACKET_HDR_SIZE;

        /* first hdr */
        addr_iter = obex_hdr_ctor_inplace(addr_iter, hdrs->hi, &hdrs->value);
        if (!addr_iter)
                goto exit_err_free;
        if (hdrs->hi == OBEX_HI_EOB)
                all = true;

        /* rest hdr */
        ohdr_init_collect *entity;
        ohdr_init_collect_for_each_entry(entity, hdrs) {
                if (entity->hi != OBEX_HI_BODY || entity->hi != OBEX_HI_EOB)
                        goto exit_err_free;
                addr_iter = obex_hdr_ctor_inplace(addr_iter, entity->hi,
                                                  &entity->value);
                if (!addr_iter)
                        goto exit_err_free;
                if (entity->hi == OBEX_HI_EOB)
                        all = true;
        }
        if (all)
                obex_set_final(&req->packet_code);
        return req;

exit_err_free:
        dtor_obex_packet(req);
        return NULL;
}

/* L                                            H */
/* [ 0x80 | 0x00 0x07 | 0x10 | 0x00 | 0xff 0xff ] */
static const uint8_t obex_mini_connect_req[OBEX_MINI_CONNECTREQ_SIZE] = {
        OBEX_REQC_CONNECT, 0x07, 0x00,
        OBEX_CURR_VERSION_NUM, 0x00,
        MAX_OBEX_PACKET_SIZE,
};

void copy_obex_mini_connect(uint8_t flags, uint16_t mpsize, void *buff, uint8_t size)
{
        assert(size >= OBEX_MINI_CONNECTREQ_SIZE);
        memcpy(buff, obex_mini_connect_req, OBEX_MINI_CONNECTREQ_SIZE);
        uint8_t *iter = buff;
        *(iter + OBEX_CONNECT_FLAGS_OFFSET) = flags;
        *((uint16_t *)(iter + OBEX_CONNECT_MPSIZE_OFFSET)) = mpsize;
}

static struct obex_packet *default_layout_get_packet_mutable(struct obex_layout_struct *handle)
{
        if (handle->p_get)
                return NULL;
        handle->p_get++;
        return handle->p;
}

static const struct obex_packet *default_layout_get_packet(struct obex_layout_struct *handle)
{
        return handle->lops->get_packet_mutable(handle);
}

static void default_layout_put_packet(struct obex_layout_struct *handle)
{
        if (handle->p_get)
                handle->p_get--;
}

/* generic obex packet builder */
static int default_layout_make_packet(struct obex_layout_struct *handle, ohdr_init_collect *hdrs)
{
        size_t psize = 0;
        void *iter = NULL;
        
        /* there been a packet */
        if (handle->allocated)
                return -EAGAIN;

        psize = OBEX_PACKET_HDR_SIZE + accumulate_hdrs_size(hdrs);
        handle->p = malloc(sizeof(uint8_t) * psize);
        if (!handle->p)
                return -ENOMEM;
        handle->packet_size = psize;
        handle->allocated = 1;

        iter = handle->p;
        iter += OBEX_PACKET_HDR_SIZE;
        iter = obex_hdr_ctor_inplace(iter, hdrs->hi, &hdrs->value);
        if (!iter)
                goto exit_err_undo;

        ohdr_init_collect *entity;
        ohdr_init_collect_for_each_entry(entity, hdrs) {
                iter = obex_hdr_ctor_inplace(iter, entity->hi, &entity->value);
                if (!iter)
                        goto exit_err_undo;
        }
        return 0;

exit_err_undo:
        free(handle->p);
        handle->p = NULL;
        handle->packet_size = 0;
        handle->allocated = 0;
        return -EAGAIN;
}

int default_layout_drop_packet(struct obex_layout_struct *handle)
{
        if (handle->p_get)
                return -EAGAIN;
        
        if (handle->allocated) {
                free(handle->p);
                handle->packet_size = 0;
                handle->allocated = 0;
                return 0;
        }

        return -EINVAL;
}

/**
 * This is the minimal requirements for Objext PUT message.
 * NAEM         => file name
 * TYPE         => file mime type
 * LENGTH       => file total size
 * CHUNK        => file data buffer
 * CHUNK_SIZE   => size of file data buffer
 * all          => should append End-Of-Body header?
 * I think we can put this into an object named agent,and PUT
 * is handled by PUT Agent.(TODO)
 */
int default_layout_mini_put(struct obex_layout_struct *handle, const char *name,
                            const char *type, size_t length, void *chunk,
                            size_t chunk_size, int all)
{
        if (handle->in_use)
                return -EAGAIN;
        
        ohdr_init_collect *hdrs = NULL, *tmp = NULL;
        struct obex_hdr_initializer v;
        int ret = 0;

#define try_build_hdrs(__hdrs, __tmp, __hi, __vp)                     \
        do {                                                          \
                if (__hdrs) {                                         \
                        __tmp = ctor_ohdr_init_collect(__hi, __vp);   \
                        if (!__tmp)                                   \
                                goto exit_err_free;                   \
                        ohdr_init_collect_add(__tmp, __hdrs);         \
                } else {                                              \
                        __hdrs = ctor_ohdr_init_collect(__hi, __vp);  \
                        if (!__hdrs)                                  \
                                goto exit_err_free;                   \
                }                                                     \
        } while (0)

        ret = -ENOMEM;
        if (name) {
                v = ctor_obex_hdr_initializer((uint64_t)name, 1, 0);
                try_build_hdrs(hdrs, tmp, OBEX_HI_NAME, &v);
        }

        ret = -ENOMEM;
        if (type) {
                v = ctor_obex_hdr_initializer((uint64_t)type, 1, 0);
                try_build_hdrs(hdrs, tmp, OBEX_HI_TYPE, &v);
        }
        
        ret = -ENOMEM;
        if (length) {
                v = ctor_obex_hdr_initializer((uint64_t)length, 1, 0);
                try_build_hdrs(hdrs, tmp, OBEX_HI_LENGTH, &v);
        }
        
        ret = -ENOMEM;
        if (chunk && chunk_size) {
                v = ctor_obex_hdr_initializer((uint64_t)chunk, 0, chunk_size);
                try_build_hdrs(hdrs, tmp, OBEX_HI_BODY, &v);
        }

        ret = -ENOMEM;
        if (all) {
                v = ctor_obex_hdr_initializer((uint64_t)NULL, 0, 0);
                try_build_hdrs(hdrs, tmp, OBEX_HI_EOB, &v);
        }

        ret = handle->lops->make_packet(handle, hdrs);
        if (ret < 0)
                goto exit_err_free;
        if (all) {
                /* we can guarantee this control path has handle->in_use == 1 */
                obex_set_final(&(handle->lops->get_packet_mutable(handle))->packet_code);
        }
        
exit_err_free:
        destroy_whole_ohdr_init_collect(hdrs);
        return ret;
        
#undef try_build_hdrs
}

/* we can not replace operations when it is working */
const struct obex_layout_ops *default_layout_replace_ops(struct obex_layout_struct *handle,
                                                   struct obex_layout_ops *new)
{
        if (!new)
                return handle->lops;
        const struct obex_layout_ops *old = handle->lops;
        handle->lops = new;
        return old;
}

/**
 * Default operations.
 */
const struct obex_layout_ops default_obex_layout_ops = {
        .get_packet = default_layout_get_packet,
        .get_packet_mutable = default_layout_get_packet_mutable,
        .put_packet = default_layout_put_packet,
        .make_packet = default_layout_make_packet,
        .drop_packet = default_layout_drop_packet,
        .replace_ops = default_layout_replace_ops,
};

/* default ctor of laytout object */
struct obex_layout_struct *ctor_obex_layout(void)
{
        struct obex_layout_struct *handle = NULL;
        handle = malloc(sizeof(struct obex_layout_struct));
        if (handle) {
                handle->p = NULL;
                handle->packet_size = 0;
                handle->p_get = 0;
                handle->allocated = 0;
                handle->in_use = 1;
                handle->lops = &default_obex_layout_ops;
        }
        return handle;
}
