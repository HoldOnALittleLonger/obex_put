#include "obex_agent_data_def.h"

#define modify_u32(__ad, __member, __new) ({   \
        uint32_t old = __ad->__member;         \
        (__ad)->__member = __new;              \
        old = old;                             \
        })

#define modify_constring(__ad, __member, __new) ({ \
        const char *old = __ad->__member;          \
        __ad->__member = __new;                    \
        old = old;                                 \
        })

/**
 * ==================
 * CONNECT Agent Data
 * ==================
 */
static uint32_t default_cad_mod_count(union obex_agent_data *cad, uint32_t new)
{
        return modify_u32(cad, cad_count, new);
}

static uint32_t default_cad_mod_length(union obex_agent_data *cad, uint32_t new)
{
        return modify_u32(cad, cad_length, new);
}

static const char *default_cad_mod_who(union obex_agent_data *cad, const char *who)
{
        return modify_constring(cad, cad_who, who);
}

static const char *default_cad_mod_target(union obex_agent_data *cad, const char *target)
{
        return modify_constring(cad, cad_target, target);
}

static const char *default_cad_mod_description(union obex_agent_data *cad,
                                                   const char *description)
{
        return modify_constring(cad, cad_description, description);
}

static uint32_t default_cad_mod_connectid(union obex_agent_data *cad, uint32_t id)
{
        return modify_u32(cad, cad_connectid, id);
}

static ohdr_init_collect *default_cad_to_hdrs(union obex_agent_data *cad)
{
        ohdr_init_collect *hdrs = NULL, *tmp = NULL, *dummy = NULL;
        struct obex_hdr_initializer v = {0};
        dummy = ctor_ohdr_init_collect(0, &v);
        if (!dummy)
                return NULL;

        if (cad->cad_connectid > 0) {
                v = ctor_obex_hdr_initializer((uint64_t)cad->cad_connectid, 1, 0);
                tmp = ctor_ohdr_init_collect(OBEX_HI_CONNECTID, &v);
                if (!tmp)
                        goto exit_free_all;
                ohdr_init_collect_add(tmp, dummy);
        }
        
        if (cad->cad_count > 0) {
                v = ctor_obex_hdr_initializer((uint64_t)cad->cad_count, 1, 0);
                tmp = ctor_ohdr_init_collect(OBEX_HI_COUNT, &v);
                if (!tmp)
                        goto exit_free_all;
                ohdr_init_collect_add(tmp, dummy);
        }

        if (cad->cad_length > 0) {
                v = ctor_obex_hdr_initializer((uint64_t)cad->cad_length, 1, 0);
                tmp = ctor_ohdr_init_collect(OBEX_HI_LENGTH, &v);
                if (!tmp)
                        goto exit_free_all;
                ohdr_init_collect_add(tmp, dummy);
        }

        if (cad->cad_who) {
                v = ctor_obex_hdr_initializer((uint64_t)cad->cad_who, 1, 0);
                tmp = ctor_ohdr_init_collect(OBEX_HI_WHO, &v);
                if (!tmp)
                        goto exit_free_all;
                ohdr_init_collect_add(tmp, dummy);
        }

        if (cad->cad_target) {
                v = ctor_obex_hdr_initializer((uint64_t)cad->cad_target, 1, 0);
                tmp = ctor_ohdr_init_collect(OBEX_HI_TARGET, &v);
                if (!tmp)
                        goto exit_free_all;
                ohdr_init_collect_add(tmp, dummy);
        }
                
        if (cad->cad_description) {
                v = ctor_obex_hdr_initializer((uint64_t)cad->cad_description, 1, 0);
                tmp = ctor_ohdr_init_collect(OBEX_HI_DESCRIPTION, &v);
                if (!tmp)
                        goto exit_free_all;
                ohdr_init_collect_add(tmp, dummy);
        }

        hdrs = ohdr_init_collect_next(dummy);
        ohdr_init_collect_del(dummy);
        dtor_ohdr_init_collect(dummy);

        /* This is OK,because dummy is a local pointer */
        if (hdrs == dummy)
                return NULL;
        else
                return hdrs;

exit_free_all:
        destroy_whole_ohdr_init_collect(dummy);
        return NULL;
}

const struct obex_cad_operations default_obex_cad_ops = {
        .mod_count = default_cad_mod_count,
        .mod_length = default_cad_mod_length,
        .mod_who = default_cad_mod_who,
        .mod_target = default_cad_mod_target,
        .mod_description = default_cad_mod_description,
        .mod_connectid = default_cad_mod_connectid,
        .to_hdrs = default_cad_to_hdrs,
        .destroy_hdrs = destroy_whole_ohdr_init_collect,
};

/**
 * ==============
 * PUT Agent Data
 * ==============
 */

static uint32_t default_pad_mod_connectid(union obex_agent_data *pad, uint32_t id)
{
        return modify_u32(pad, pad_connectid, id);
}

static const char *default_pad_mod_name(union obex_agent_data *pad, const char *name)
{
        return modify_constring(pad, pad_name, name);
}

static const char *default_pad_mod_type(union obex_agent_data *pad, const char *type)
{
        return modify_constring(pad, pad_type, type);
}

static uint32_t default_pad_mod_length(union obex_agent_data *pad, uint32_t length)
{
        return modify_u32(pad, pad_length, length);
}

static void *default_pad_mod_chunk(union obex_agent_data *pad, void *chunk)
{
        void *old = pad->pad_chunk;
        pad->pad_chunk = chunk;
        return old;
}

static size_t default_pad_mod_chunk_size(union obex_agent_data *pad, size_t chunk_size)
{
        size_t old = pad->pad_chunk_size;
        pad->pad_chunk_size = chunk_size;
        return old;
}

static ohdr_init_collect *default_pad_to_hdrs(union obex_agent_data *pad)
{
        ohdr_init_collect *hdrs = NULL, *tmp = NULL, *dummy = NULL;
        struct obex_hdr_initializer v = {0};
        dummy = ctor_ohdr_init_collect(0, &v);
        if (!dummy)
                return NULL;

        if (pad->pad_connectid > 0) {
                v = ctor_obex_hdr_initializer((uint64_t)pad->pad_connectid, 1, 0);
                tmp = ctor_ohdr_init_collect(OBEX_HI_CONNECTID, &v);
                if (!tmp)
                        goto exit_free_all;
                ohdr_init_collect_add(tmp, dummy);
        }

        if (pad->pad_name) {
                v = ctor_obex_hdr_initializer((uint64_t)pad->pad_name, 1, 0);
                tmp = ctor_ohdr_init_collect(OBEX_HI_NAME, &v);
                if (!tmp)
                        goto exit_free_all;
                ohdr_init_collect_add(tmp, dummy);
        }
        
        if (pad->pad_length > 0) {
                v = ctor_obex_hdr_initializer((uint64_t)pad->pad_length, 1, 0);
                tmp = ctor_ohdr_init_collect(OBEX_HI_LENGTH, &v);
                if (!tmp)
                        goto exit_free_all;
                ohdr_init_collect_add(tmp, dummy);
        }

        if (pad->pad_type) {
                v = ctor_obex_hdr_initializer((uint64_t)pad->pad_type, 1, 0);
                tmp = ctor_ohdr_init_collect(OBEX_HI_TYPE, &v);
                if (!tmp)
                        goto exit_free_all;
                ohdr_init_collect_add(tmp, dummy);
        }

        /* for PUT,there at least one hdr will exists */
        v = ctor_obex_hdr_initializer((uint64_t)pad->pad_chunk, 0, pad->pad_chunk_size);
        if (pad->pad_chunk == NULL && pad->pad_chunk_size == 0)
                tmp = ctor_ohdr_init_collect(OBEX_HI_EOB, &v);
        else
                tmp = ctor_ohdr_init_collect(OBEX_HI_BODY, &v);
        if (!tmp)
                goto exit_free_all;
        ohdr_init_collect_add(tmp, dummy);

        hdrs = ohdr_init_collect_next(dummy);
        ohdr_init_collect_del(dummy);
        dtor_ohdr_init_collect(dummy);
        return hdrs;

exit_free_all:
        destroy_whole_ohdr_init_collect(dummy);
        return NULL;
}

const struct obex_pad_operations default_obex_pad_ops = {
        .mod_connectid = default_pad_mod_connectid,
        .mod_name = default_pad_mod_name,
        .mod_type = default_pad_mod_type,
        .mod_length = default_pad_mod_length,
        .mod_chunk = default_pad_mod_chunk,
        .mod_chunk_size = default_pad_mod_chunk_size,
        .to_hdrs = default_pad_to_hdrs,
        .destroy_hdrs = destroy_whole_ohdr_init_collect,
};
                                              
