#include <stdint.h>

#include "obex_packet_def.h"
#include "obex_impl.h"
#include "obex_layout.h"

static size_t accumulate_hdrs_size(ohdr_init_collect *hdrs, bool denil)
{
        size_t hdr_size = 0;
        size_t value_size = 0;
        ohdr_init_collect *entity;
        ohdr_init_collect_for_each_entry(entity, hdrs) {
                value_size = obex_hdr_probe_initializer_size(entity->hi,
                                                             &entity->value);
                hdr_size += obex_hdr_compute_size(entity->hi, value_size);
                if (denil)
                        hdr_size -= 1;
                else if (obex_hdr_no_nil(entity->hi))
                        hdr_size -= 1;
        }
        value_size = obex_hdr_probe_initializer_size(hdrs->hi, &hdrs->value);
        hdr_size += obex_hdr_compute_size(hdrs->hi, value_size);
        if (denil)
                hdr_size -= 1;
        else if (obex_hdr_no_nil(hdrs->hi))
                hdr_size -= 1;

        return hdr_size;
}

static inline size_t accumulate_hdrs_size_nonil(ohdr_init_collect *hdrs)
{
        return accumulate_hdrs_size(hdrs, true);
}
static inline size_t accumulate_hdrs_size_hasnil(ohdr_init_collect *hdrs)
{
        return accumulate_hdrs_size(hdrs, false);
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
        size_t hdr_size = accumulate_hdrs_size_hasnil(hdrs);
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
        
        size_t hdr_size = accumulate_hdrs_size_nonil(hdrs);
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

/**
 * layout to make a minimal CONNECT packet.
 */
obex_request_t *ctor_obex_connect_request(uint8_t vern, uint8_t flags,
                                          uint16_t mpsize, size_t opt_size)
{
        size_t data_size = 1 + sizeof(flags) + sizeof(mpsize) + opt_size;
        size_t req_size = obex_packet_compute_size(data_size);
        obex_request_t *req = ctor_obex_packet(OBEX_REQC_CONNECT, req_size);
        if (!req)
                return NULL;

        uint8_t *req_iter = (uint8_t *)req;
        /* skip packet header */
        req_iter += OBEX_PACKET_HDR_SIZE;
        
        *req_iter = vern;
        ++req_iter;
        *req_iter = flags;
        ++req_iter;
        *((uint16_t *)req_iter) = mpsize;
        return req;
}
