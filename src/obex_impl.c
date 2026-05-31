#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <iconv.h>

#include "obex_packet_def.h"
#include "obex_impl.h"

#define UM_CONFIG_CONTAINER_OF
#include "utility_macro.h"
#include "list_head.h"

/**
 * obex_hdr_field_pointer_t - hdr member pointers
 * @u8p:                      points to 1B value or text string
 * @u16p:                     always points to 2B value,such length prefix
 * @u32p:                     points to 4B value,such LENGTH hdr's value
 * @voidp:                    points to chunk
 */
typedef union {
        uint8_t *u8p;
        uint16_t *u16p;
        uint32_t *u32p;
        void *voidp;
} obex_hdr_field_pointer_t;

#define obex_hdr_fp_set(__lhs, __rhs)         \
        do {                                  \
                (__lhs) = (void *)__rhs;      \
        } while (0)

#define obex_hdr_fp_set_u8(__fpp, __address) \
        obex_hdr_fp_set((__fpp)->u8p, __address)

#define obex_hdr_fp_set_u16(__fpp, __address) \
        obex_hdr_fp_set((__fpp)->u16p, __address)

#define obex_hdr_fp_set_u32(__fpp, __address) \
        obex_hdr_fp_set((__fpp)->u32p, __address)

#define obex_hdr_fp_set_void(__fpp, __address) \
        obex_hdr_fp_set((__fpp)->voidp, __address)

#define obex_hdr_fp_get_u8(__fpp) ({ \
        (__fpp)->u8p = (__fpp)->u8p; \
        })

#define obex_hdr_fp_get_u16(__fpp) ({  \
        (__fpp)->u16p = (__fpp)->u16p; \
        })

#define obex_hdr_fp_get_u32(__fpp) ({  \
        (__fpp)->u32p = (__fpp)->u32p; \
        })

#define obex_hdr_fp_get_void(__fpp) ({   \
        (__fpp)->voidp = (__fpp)->voidp; \
        })

/**
 * obex_hdr_visitor - vistor for access to obex hdr's member
 * @hdr:              header
 * @idx:              idx to the member in headr
 * return:            object of type obex_hdr_field_pointer_t is
 *                    returned by value
 * # unknown pattern of @hdr cause assert(false) because obex_hdr_pattern_mapper(),
 *   or because invalid @idx to obex_hdr_member_offset().
 */
static obex_hdr_field_pointer_t obex_hdr_visitor(struct obex_header *hdr, uint8_t idx)
{
        obex_hdr_field_pointer_t fp = {0};
        uint8_t *member_address = hdr->hv;
        enum obex_hdr_pattern p = obex_hdr_pattern_mapper(hdr->hi);
        uint8_t member_offset = obex_hdr_member_offset(p, idx);
        member_address += member_offset;
        switch (p) {
        case OBEX_HDR_PATTERN_00:
        case OBEX_HDR_PATTERN_01:
                if (!idx) {
                        obex_hdr_fp_set_u16(&fp, member_address);
                } else {
                        if (hdr->hi == OBEX_HI_BODY || hdr->hi == OBEX_HI_EOB) {
                                obex_hdr_fp_set_void(&fp, member_address);
                        } else {
                                obex_hdr_fp_set_u8(&fp, member_address);
                        }
                }
                break;
        case OBEX_HDR_PATTERN_10:
                obex_hdr_fp_set_u8(&fp, member_address);
                break;
        case OBEX_HDR_PATTERN_11:
                obex_hdr_fp_set_u32(&fp, member_address);
        }
        return fp;
}

/* inplace NAME header constructor */
void *obex_hdr_ctor_name_inplace(struct obex_header *hdr,
                                 const struct obex_hdr_initializer *value)
{
        char *text = (char *)value->small_size_initializer;
        size_t text_len = strlen(text);
        size_t hdr_size = obex_hdr_compute_size(hdr->hi, text_len);
        size_t utf16_buff_size = obex_hdr_value_size(hdr, hdr_size);
        char *utf16_be_buff = malloc(sizeof(char) * utf16_buff_size);
        if (!utf16_be_buff)
                return NULL;

        char *buff_iter = utf16_be_buff;
        size_t buffer_size = utf16_buff_size;
        iconv_t filter = iconv_open("UTF-16BE", "UTF-8");
        if (filter == (iconv_t)-1)
                goto exit_err_free;

        /* include null terminate */
        ++text_len;
        /* convert to UTF-16BE from UTF-8 */
        if (iconv(filter, &text, &text_len, &buff_iter, &buffer_size)
            == (size_t)-1)
                goto exit_err_free;
        iconv_close(filter);
        
        obex_hdr_field_pointer_t fp = {0};
        fp = obex_hdr_visitor(hdr, OBEX_HDR_MEMBER0);
        *obex_hdr_fp_get_u16(&fp) = htons(hdr_size);
        fp = obex_hdr_visitor(hdr, OBEX_HDR_MEMBER1);
        memmove(obex_hdr_fp_get_u8(&fp), utf16_be_buff, utf16_buff_size);
        
        free(utf16_be_buff);
        return (uint8_t *)hdr + hdr_size;
        
exit_err_free:
        free(utf16_be_buff);
        return NULL;
}

void *obex_hdr_ctor_type_inplace(struct obex_header *hdr,
                                 const struct obex_hdr_initializer *value)
{
        char *type_string = (char *)value->small_size_initializer;
        size_t string_len = strlen(type_string);
        size_t hdr_size = obex_hdr_compute_size(hdr->hi, string_len);
        obex_hdr_field_pointer_t fp = {0};
        fp = obex_hdr_visitor(hdr, OBEX_HDR_MEMBER0);
        *obex_hdr_fp_get_u16(&fp) = htons(hdr_size);
        fp = obex_hdr_visitor(hdr, OBEX_HDR_MEMBER1);
        strncpy(obex_hdr_fp_get_u8(&fp), type_string, string_len);
        return (uint8_t *)hdr + hdr_size;
}

void *obex_hdr_ctor_body_inplace(struct obex_header *hdr,
                                 const struct obex_hdr_initializer *value)
{
        void *chunk = (void *)value->large_size_initializer;
        size_t chunk_size = value->initializer_size;
        
        /* because BODY has no null-terminate */
        size_t hdr_size = obex_hdr_compute_size(hdr->hi, chunk_size) - 1;
        
        obex_hdr_field_pointer_t fp = {0};
        fp = obex_hdr_visitor(hdr, OBEX_HDR_MEMBER0);
        *obex_hdr_fp_get_u16(&fp) = htons(hdr_size);
        fp = obex_hdr_visitor(hdr, OBEX_HDR_MEMBER1);
        /**
         * if the chunk size is zero,no memory move happens.
         * this will happens when the last EOB has no valid data.
         */
        memmove(obex_hdr_fp_get_void(&fp), chunk, chunk_size);
        return (uint8_t *)hdr + hdr_size;
}

void *obex_hdr_ctor_length_inplace(struct obex_header *hdr,
                                   const struct obex_hdr_initializer *value)
{
        uint32_t length_value = value->small_size_initializer;
        size_t hdr_size = obex_hdr_compute_size(hdr->hi, sizeof(length_value));
        obex_hdr_field_pointer_t fp = {0};
        fp = obex_hdr_visitor(hdr, OBEX_HDR_MEMBER0);
        *obex_hdr_fp_get_u32(&fp) = htonl(length_value);
        return (uint8_t *)hdr + hdr_size;
}

/**
 * inplace initialization entrypoint.
 * we requires all inplace constructor returns
 * an advanced pointer to the next to end of the hdr,
 * this will useful when we need to make packet layout.
 * and all of them should return NULL if cant to initialize
 * hdr
 */
void *obex_hdr_ctor_inplace(void *hdr, uint8_t hi,
                            const struct obex_hdr_initializer *value)
{
        struct obex_header *ohdr = (struct obex_header *)hdr;
        ohdr->hi = hi;
        return obex_hdr_ctor_inplace_dispatcher(ohdr, value);
}

/**
 * obex_hdr_probe_size - probe the size of value represented by the
 *                       hdr initializer
 * @hi:                  hdr type
 * @p:                   hdr pattern
 * @v:                   value
 * return:               size of value in initializer
 *                       for short text string,we do scanning on it.
 *                       for 1B / 4B integer,we just return sizeof.
 *                       for chunk,we return @initializer_size.
 */
size_t obex_hdr_probe_size(uint8_t hi, enum obex_hdr_pattern p,
                           const struct obex_hdr_initializer *v)
{
        switch (p) {
        case OBEX_HDR_PATTERN_00: {
                const char *textp = (const char *)v->small_size_initializer;
                return strlen(textp);
        }
        case OBEX_HDR_PATTERN_01:
                switch (hi) {
                case OBEX_HI_BODY:
                case OBEX_HI_EOB:
                        return v->initializer_size;
                default: {
                        const char *textp = (const char *)v->small_size_initializer;
                        return strlen(textp);
                }
                }
        case OBEX_HDR_PATTERN_10:
                return sizeof(uint8_t);
        case OBEX_HDR_PATTERN_11:
                return sizeof(uint32_t);
        }
}

/* destory whole collection */
void destroy_whole_ohdr_init_collect(ohdr_init_collect *head)
{
        ohdr_init_collect *entity = NULL;
        ohdr_init_collect *tmp = NULL;
        list_for_each_entry_safe(entity, tmp, &head->list, list) {
                ohdr_init_collect_del(entity);
                dtor_ohdr_init_collect(entity);
        }
        dtor_ohdr_init_collect(head);
}
