#define UM_CONFIG_LIKELY

#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "obex_packet_def.h"
#include "obex_impl.h"
#include "obex_layout.h"

#include "utility_macro.h"

/**
 * Account the total size of hdrs in initializer list
 */
static size_t accumulate_hdrs_size(ohdr_init_collect *hdrs)
{
        size_t hdr_size = 0;
        size_t value_size = 0;
        ohdr_init_collect *entity;
        size_t tmp_size = 0;
        ohdr_init_collect_for_each_entry(entity, hdrs) {
                value_size = obex_hdr_probe_initializer_size(entity->hi,
                                                             &entity->value);
                hdr_size += obex_hdr_compute_size(entity->hi, value_size);
        }
        value_size = obex_hdr_probe_initializer_size(hdrs->hi, &hdrs->value);
        hdr_size += obex_hdr_compute_size(hdrs->hi, value_size);
        return hdr_size;
}

/* L                                            H */
/* [ 0x80 | 0x00 0x07 | 0x10 | 0x00 | 0xff 0xff ] */
static const uint8_t obex_mini_connect_req[OBEX_MINI_CONNECTREQ_SIZE] = {
        /* operation code AND frame size */
        OBEX_REQC_CONNECT, 0x00, 0x07,
        
        /* obex version AND flags */
        OBEX_CURR_VERSION_NUM, 0x00,
        
        /* maximumal obex packet size */
        /* default to 1024kB */        
        0x04, 0x00,
}; 

/* deferene from minimal EOB request,we may need to configure
 * the connect request.
 */
void copy_obex_mini_connect(uint8_t flags, uint16_t mpsize, void *buff, uint8_t size)
{
        assert(size >= OBEX_MINI_CONNECTREQ_SIZE);
        memcpy(buff, obex_mini_connect_req, OBEX_MINI_CONNECTREQ_SIZE);
        uint8_t *iter = buff;
        *(iter + OBEX_CONNECT_FLAGS_OFFSET) = flags;
        *((uint16_t *)(iter + OBEX_CONNECT_MPSIZE_OFFSET)) = mpsize;
}

/* invariant */
const uint8_t obex_mini_eob_req[OBEX_PACKET_HDR_SIZE + OBEX_PACKET_HDR_SIZE] = {
        0x82, 0x00, 0x06,
        OBEX_HI_EOB, 0x00, 0x03,
};


/**
 * ======================
 * OBEX Layout Operations
 * ======================
 */
/* we can get packet,if it is not in use */
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

/**
 * Generic obex packet builder.
 * Usually,we do not need to re-allocate packet memory,because
 * a layout object is created for a specified operation.
 */
static int default_layout_make_packet(struct obex_layout_struct *handle, uint8_t code, ohdr_init_collect *hdrs)
{
        size_t psize = 0;
        void *iter = NULL;
        int local_allocated = 0;
        int ret = 0;

        /* in use */
        if (handle->p_get)
                return -EAGAIN;
        
        psize = OBEX_PACKET_HDR_SIZE + accumulate_hdrs_size(hdrs);

        /* if we need to allocate memory? */
        if (!handle->allocated) {
                handle->p = malloc(sizeof(uint8_t) * psize);
                if (!handle->p)
                        return -ENOMEM;
                handle->packet_size = psize;
                handle->allocated = 1;
                local_allocated = 1;
        }

        /* we require the buffer size is large enough to store the next packet */
        if (handle->packet_size < psize) {
                ret = -EFAULT;
                goto exit_err_undo;
        }
                
        memset(handle->p, 0, handle->packet_size);
        handle->p->packet_code = code;
        handle->p->packet_len_netord = htons(psize);

        ret = -EFAULT;

        /* set headers */
        iter = handle->p;
        iter += OBEX_PACKET_HDR_SIZE;
        iter = obex_hdr_ctor_inplace(iter, hdrs->hi, &hdrs->value);
        if (um_unlikely(!iter))
                goto exit_err_undo;

        /* set rest */
        ohdr_init_collect *entity;
        ohdr_init_collect_for_each_entry(entity, hdrs) {
                iter = obex_hdr_ctor_inplace(iter, entity->hi, &entity->value);
                if (um_unlikely(!iter))
                        goto exit_err_undo;
        }
        ret = 0;
        return 0;

exit_err_undo:
        if (local_allocated) {
                free(handle->p);
                handle->p = NULL;
                handle->packet_size = 0;
                handle->allocated = 0;
        }
        return ret;
}

int default_layout_drop_packet(struct obex_layout_struct *handle)
{
        if (handle->p_get)
                return -EBUSY;
        
        if (handle->allocated) {
                free(handle->p);
                handle->packet_size = 0;
                handle->allocated = 0;
                return 0;
        }
        return -EINVAL;
}

/* we can not replace operations when it is working */
const struct obex_layout_operations *default_layout_replace_ops(struct obex_layout_struct *handle,
                                                   struct obex_layout_operations *new)
{
        if (!new)
                return handle->lops;
        const struct obex_layout_operations *old = handle->lops;
        handle->lops = new;
        return old;
}

/**
 * Default operations.
 */
const struct obex_layout_operations default_obex_layout_ops = {
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
                handle->refcnt = 1;
                handle->lops = &default_obex_layout_ops;
        }
        return handle;
}
