#ifndef _OBEX_IMPL_H_
#define _OBEX_IMPL_H_

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "obex_packet_def.h"

#define UM_CONFIG_CONTAINER_OF
#include "utility_macro.h"
#include "list_head.h"

/**
 * There are four possible patterns of the obex header.
 *   00 => 1B hi + 2B length + UTF-16BE string(null terminate)
 *   01 => 1B hi + 2B length + Byte sequence(null terminate)
 *   10 => 1B hi + 1B value
 *   11 => 1B hi + 4B value
 * We can make a map,and map the @hi to pattern.
 * For example,NAME header has form [ hi | length | UTF-16BE ].
 * and @hi of NAME header,the 7-th and 6-th bits composed
 * "00",so NAME is mapped to 00-pattern.
 * The initializers for each pattern should difference.
 * But we can use the same initializer to 00-pattern and 01-pattern.
 *   initializer => { const char *text }
 * Similarly,we can use the same initializer to 10-pattern and 11-pattern.
 *   initializer => { uint32_t value }
 * For 00-pattern and 01-pattern,we requires the constructor
 * handles them in different,00-pattern,the memory will occupied
 * by header is "1B hi + 2B length + UTF16_SIZE(strlen(@text) + 1B null-terminate)".
 * There only two patterns have variable header size,00 and 01.
 *   obex_hdr_pttr_00_size(__text_size)
 *     => hi_size + len_size + 2 * __text_size + 2(null-terminate or not null)
 *   obex_hdr_pttr_01_size(__text_size)
 *     => hi_size + len_size + __text_size + 1(null-terminate) OR 0(not null)
 * There are two patterns have fixed size,10 and 11
 *   obex_hdr_pttr_10_size => 2B
 *   obex_hdr_pttr_11_size => 5B
 * The underlying type of "const char *" is unsigned long as usually,
 * we can assume it is uint64_t.
 * So,we can use only one kind of initializer to initialize header.
 *
 * Note that,because BODY hdr has no null-terminate,we may
 * need a size value to indicates how long the sequence is.
 * But this will broken the consistence with string type,
 * so we requires the initializer constructor always treat
 * the real data like a string,and in-place scan the string
 * get the size of chunk.
 * But this process is time costly,thus,we can put a size
 * indicator in initializer,use union wrap them.
 * Hence,the BODY in-place constructor will knows access to
 * the size indicator instead scan the chunk to get real size.
 * The chunk size should be known previously before we
 * prepare to construct packet.
 * If we follow this rule,the in-place constructor should works
 * correctly.
 *   small data no size indicator
 *   large data has size indicator
 * 
 * How to interpret the initializer is hand over to constructor.
 * In constructor,we convert the initializer type depends on its pattern,
 * and pass the initializer and the hdr position to helper.
 *
 * We almost do not need to construct an individual hdr object,because
 * each hdr must be wrapped into a packet,so in-place construction
 * is the most case.
 * If we need to construct a packet with more than one hdrs,
 * we can make a collection to the initializers,and construct
 * each part.
 * Through this method,we can define some layouts,that describes
 * how the packet is composed.
 * For example,we want a PUT packet,so we can let the layout
 * has the style
 *   [ code | packet len | NAME hdr | TYPE hdr | LENGTH hdr | BODY hdr ]
 * Now we collects the hdrs in the collection.
 *                   NAME hdr
 *                  /        \
 *                 /          \
 *                /           TYPE hdr
 *              BODY hdr       |
 *                  \         /
 *                   \       /
 *                   LENGTH hdr
 * Then make use of a loop,to initialize each hdr in the packet.
 * Because packet memory is allocated on demande,so we knows the
 * sizes of each hdr,then we can easy to advance pointer step
 * to next hdr until all initializers are consumed.
 *
 * Follow this abstraction,we will no longer need to list all
 * header types in visitor,only need to handle four cases.
 * The element type of headers is classified to four type
 *   uint8_t *    =>  string or 1B data
 *   uint16_t *   =>  2B data,always length field
 *   uint32_t *   =>  4B data,always length field
 *   void *       =>  chunk
 * What the field pointer points to is determined by current
 * pattern.
 *   fp = obex_hdr_visitor(hdr)
 *        #^ maps @hdr->hi to pattern
 *        #  compute offset to the field,
 *        #  assign the @fp with the field addres in @hdr
 *        #  @fp = @hv + offset
 * So,we also need to classify the offset(s) through
 * pattern.
 * Because the @hi is contained by each hdr,we skip it,and
 * let the idx of member start from the @hv,initial idx is 0,
 * offset relative to @hv is 0.
 * There at least has one member,at most has two member,
 * so @idx would not equal to 2,otherwise,it is illegal.
 * Now,we no longer need the size definitions of each fields
 * of each header type.
 */

/* invariant size */
#define OBEX_HDR_HI_SIZE 1U
#define OBEX_HDR_FIXED_LENGTH_SIZE 2U
#define OBEX_HDR_PATTERN10_FIXED_LENGTH_SIZE 1U
#define OBEX_HDR_PATTERN11_FIXED_LENGTH_SIZE 4U
#define OBEX_PACKET_HDR_SIZE 3U

/* four patterns */
enum obex_hdr_pattern {
        OBEX_HDR_PATTERN_00,
        OBEX_HDR_PATTERN_01,
        OBEX_HDR_PATTERN_10,
        OBEX_HDR_PATTERN_11,
};

/* idxs */
enum {
        OBEX_HDR_MEMBER0,
        OBEX_HDR_MEMBER1,
};

/* map @hi to pattern */
static enum obex_hdr_pattern obex_hdr_pattern_mapper(uint8_t hi)
{
        switch (hi) {
        case OBEX_HI_NAME:
                return OBEX_HDR_PATTERN_00;
        case OBEX_HI_TYPE:
        case OBEX_HI_BODY:
        case OBEX_HI_EOB:
                return OBEX_HDR_PATTERN_01;
        case OBEX_HI_LENGTH:
                return OBEX_HDR_PATTERN_11;
        default:
                assert(0);
        }
}

/* get member offset to @hv for given pattern */
static inline uint8_t obex_hdr_member_offset(enum obex_hdr_pattern p, uint8_t idx)
{
        if (idx > 1)
                assert(0);
        
        switch (p) {
        case OBEX_HDR_PATTERN_00:
        case OBEX_HDR_PATTERN_01:
                switch (idx) {
                case 0:
                        return 0;
                case 1:
                        return OBEX_HDR_FIXED_LENGTH_SIZE;
                }
        case OBEX_HDR_PATTERN_10:
        case OBEX_HDR_PATTERN_11:
                /* 10 11 pattern only allows idx 0 */
                if (idx)
                        assert(0);
                return 0;
        }
}

/**
 * obex_hdr_initializer - this structures contains value/pointer
 *                        that will be needed for initialize a
 *                        certain hdr.
 * @small_size_initializer:
 *                        1B / 2B / 4B integer
 *                        short text string null-terminate
 * @initializer_size:     chunk size
 * @large_size_initializer:
 *                        the value is not @small_size_initializer,
 *                        such BODY / EOB chunk.
 *                        we use @initializer_size to represents
 *                        chunk size,do not do any scanning on
 *                        the chunk because they are not null-terminate.
 */
struct obex_hdr_initializer {
        union {
                struct {
                        uint64_t small_size_initializer;
                };
                struct {
                        size_t initializer_size;
                        uint64_t large_size_initializer;
                };
        };
};

extern size_t obex_hdr_probe_size(uint8_t, enum obex_hdr_pattern,
                                  const struct obex_hdr_initializer *);

/* probe value size */
static inline size_t obex_hdr_probe_initializer_size(uint8_t hi,
                                                     const struct obex_hdr_initializer *v)
{
        enum obex_hdr_pattern p = obex_hdr_pattern_mapper(hi);
        return obex_hdr_probe_size(hi, p, v);
}

/**
 * ctor_obex_hdr_initializer - constructor of obex hdr initializer type
 * @value:                     inner value
 * @is_small:                  small or large
 * @value_size:                chunk size for large chunk
 * return:                     obex_hdr_initializer object returns by value
 * # no @is_small AND @value_size.
 */
static inline struct obex_hdr_initializer
ctor_obex_hdr_initializer(uint64_t value, uint8_t is_small, size_t value_size)
{
        if (is_small && value_size)
                assert(0);

        if (is_small) {
                struct obex_hdr_initializer x = {
                        .small_size_initializer = value,
                };
                return x;
        } else {
                struct obex_hdr_initializer x = {
                        .initializer_size = value_size,
                        .large_size_initializer = value,
                };
                return x;
        }
}

/**
 * obex_hdr_initializer_collect - collection of obex hdr initializers
 * @hi:                           hi of current hdr
 * @value:                        value used to initialize hdr
 * @list:                         embedded list
 */
struct obex_hdr_initializer_collect {
        uint8_t hi;
        struct obex_hdr_initializer value;
        struct list_head list;
};

typedef struct obex_hdr_initializer_collect ohdr_init_collect;

/* obex hdr initializer collect element constructor */
static inline ohdr_init_collect *
ctor_ohdr_init_collect(uint8_t hi, struct obex_hdr_initializer *value)
{
        ohdr_init_collect *head = malloc(sizeof(ohdr_init_collect));
        if (!head)
                return NULL;
        head->hi = hi;
        head->value = *value;
        INITIALIZE_LIST_HEAD(&head->list);
        return head;
}

/* obex hdr initializer collect element destructor */
static inline void dtor_ohdr_init_collect(ohdr_init_collect *entity)
{
        free(entity);
}

/* add into collection */
static inline void ohdr_init_collect_add(ohdr_init_collect *new,
                                         ohdr_init_collect *head)
{
        /**
         * we add new element to the tail,because we want the
         * object is ordered.
         *   object1 <=> object2 <=> ... objectN <=> head <=> ...
         * iterate list from left to right
         *   head => object1 => object2 => ... objectN
         */
        list_add_tail(&new->list, &head->list);
}

/* remove from collection */
static inline void ohdr_init_collect_del(ohdr_init_collect *entity)
{
        list_del(&entity->list);
}

extern void destroy_whole_ohdr_init_collect(ohdr_init_collect *);

/**
 * macro used to traverse each element in the collection,start from
 * entity next to head.
 */
#define ohdr_init_collect_for_each_entry(__entryp, __headp) \
        list_for_each_entry(__entryp, &(__headp)->list, list)



/* 00 size => UTF-16BE */
#define obex_hdr_pattern_00_size(__value_size) ({ \
        size_t __size = OBEX_HDR_HI_SIZE +        \
                OBEX_HDR_FIXED_LENGTH_SIZE +      \
                2 * __value_size + 2;             \
        __size = __size;                          \
        })

/**
 * we may waste 1 byte because null-terminate,
 * but we can let in-place constructor to handles
 * this.
 * actually,there is only a few kind of hdr is
 * no null-terminate,such BODY,but as convention,
 * we put the hdr at the tail of packet.
 * if hdr is null-terminate appending,this will
 * get the correct hdr size.
 * if hdr is not null-terminate appending,this
 * will get the result that corret hdr size + 1 .
 */
#define obex_hdr_pattern_01_size(__value_size) ({ \
        size_t __size = OBEX_HDR_HI_SIZE +        \
                OBEX_HDR_FIXED_LENGTH_SIZE +      \
                __value_size + 1;                 \
        __size = __size;                          \
        })

/* simply return fixed size */
#define obex_hdr_pattern_10_size(__unused) ({           \
        size_t __size = OBEX_HDR_HI_SIZE +              \
                OBEX_HDR_PATTERN10_FIXED_LENGTH_SIZE;   \
        __size = __size;                                \
        })

#define obex_hdr_pattern_11_size(__unused) ({           \
        size_t __size = OBEX_HDR_HI_SIZE +              \
                OBEX_HDR_PATTERN11_FIXED_LENGTH_SIZE;   \
        __size = __size;                                \
        })

/**
 * return a boolean value to indicates whether or not
 * the hdr has no null-terminate appending.
 * true => no null
 * false => has null
 */
static inline bool obex_hdr_no_nil(uint8_t hi)
{
        switch (obex_hdr_pattern_mapper(hi)) {
        case OBEX_HDR_PATTERN_01:
                switch (hi) {
                case OBEX_HI_BODY:
                case OBEX_HI_EOB:
                        return true;
                }
        }
        return false;
}

/**
 * obex_hdr_compute_size - compute the total hdr size
 * @hi:                    hdr type
 * @value_size:            hdr's value size
 * return:                 the size of hdr that includes
 *                         fixed length size if has.
 */
static inline size_t obex_hdr_compute_size(uint8_t hi, size_t value_size)
{
        enum obex_hdr_pattern p = obex_hdr_pattern_mapper(hi);
        switch (p) {
        case OBEX_HDR_PATTERN_00:
                return obex_hdr_pattern_00_size(value_size);
        case OBEX_HDR_PATTERN_01:
                return obex_hdr_pattern_01_size(value_size);
        case OBEX_HDR_PATTERN_10:
                return obex_hdr_pattern_10_size(value_size);
        case OBEX_HDR_PATTERN_11:
                return obex_hdr_pattern_11_size(value_size);
        default:
                assert(0);
        }
}

/**
 * obex_hdr_value_size - get value size of the hdr through its type and
 *                       its total size
 * @hdr:                 the header
 * @hdr_size:            header size
 * return:               value size(contains null-terminate of 01 pattern)
 */
static inline size_t obex_hdr_value_size(const struct obex_header *hdr,
                                         size_t hdr_size)
{
        switch (obex_hdr_pattern_mapper(hdr->hi)) {
        case OBEX_HDR_PATTERN_00:
        case OBEX_HDR_PATTERN_01:
                return hdr_size - OBEX_HDR_HI_SIZE - OBEX_HDR_FIXED_LENGTH_SIZE;
        case OBEX_HDR_PATTERN_10:
        case OBEX_HDR_PATTERN_11:
                return hdr_size - OBEX_HDR_HI_SIZE;
        default:
                assert(0);        
        }
}

extern void *obex_hdr_ctor_name_inplace(struct obex_header *,
                                        const struct obex_hdr_initializer *);
/* 00 dispatcher */
static void *obex_hdr_ctor_pattern_00_dispatcher(struct obex_header *hdr,
                                                 const struct obex_hdr_initializer *value)
{
        switch (hdr->hi) {
        case OBEX_HI_NAME:
                return obex_hdr_ctor_name_inplace(hdr, value);
        default:
                assert(0); 
        }
}

extern void *obex_hdr_ctor_type_inplace(struct obex_header *,
                                        const struct obex_hdr_initializer *);
extern void *obex_hdr_ctor_body_inplace(struct obex_header *hdr,
                                        const struct obex_hdr_initializer *);
/* 01 dispatcher */
static void *obex_hdr_ctor_pattern_01_dispatcher(struct obex_header *hdr,
                                                 const struct obex_hdr_initializer *value)
{
        switch (hdr->hi) {
        case OBEX_HI_BODY:
        case OBEX_HI_EOB:
                return obex_hdr_ctor_body_inplace(hdr, value);
        case OBEX_HI_TYPE:
                return obex_hdr_ctor_type_inplace(hdr, value);
        default:
                assert(0);
        }
}

/* un-implemented */
static void *obex_hdr_ctor_pattern_10_dispatcher(struct obex_header *hdr,
                                                 const struct obex_hdr_initializer *value)
{
        switch (hdr->hi) {
        default:
                assert(0);
        }
}

extern void *obex_hdr_ctor_length_inplace(struct obex_header *hdr,
                                          const struct obex_hdr_initializer *);
/* 11 dispatcher */
static void *obex_hdr_ctor_pattern_11_dispatcher(struct obex_header *hdr,
                                                 const struct obex_hdr_initializer *value)
{
        switch (hdr->hi) {
        case OBEX_HI_LENGTH:
                return obex_hdr_ctor_length_inplace(hdr, value);
        default:
                assert(0);
        }
}

/* inplace constructor stub */
static inline void *obex_hdr_ctor_inplace_dispatcher(struct obex_header *hdr,
                                                     const struct obex_hdr_initializer *value)
{
        switch (obex_hdr_pattern_mapper(hdr->hi)) {
        case OBEX_HDR_PATTERN_00:
                return obex_hdr_ctor_pattern_00_dispatcher(hdr, value);
        case OBEX_HDR_PATTERN_01:
                return obex_hdr_ctor_pattern_01_dispatcher(hdr, value);
        case OBEX_HDR_PATTERN_10:
                return obex_hdr_ctor_pattern_10_dispatcher(hdr, value);
        case OBEX_HDR_PATTERN_11:
                return obex_hdr_ctor_pattern_11_dispatcher(hdr, value);
        default:
                assert(0);
        }
}

extern void *obex_hdr_ctor_inplace(void *, uint8_t,
                                   const struct obex_hdr_initializer *);
/**
 * return packet hdr size + data size 
 */
#define obex_packet_compute_size(__data_size) ({ \
        size_t __psize = OBEX_PACKET_HDR_SIZE    \
                + (__data_size);                 \
        __psize = __psize;                       \
        })

/* constructor of obex packet */
static inline
struct obex_packet *ctor_obex_packet(uint8_t code, size_t size)
{
        struct obex_packet *p = malloc(sizeof(uint8_t) * size);
        if (!p)
                return NULL;
        p->packet_code = code;
        p->packet_len_netord = htons(size);
        return p;
}

/* destructor of obex packet */
static inline
void dtor_obex_packet(struct obex_packet *packet)
{
        free(packet);
}

//#define obex_set_bit(__uintvp, __bitn)            \
//        do {                                        \
//                (*__uintvp) |= (1U << (__bitn));    \
//        } while (0)

#define obex_set_final(__uint8vp)        \
        do {                             \
                *(__uint8vp) |= 0x80;    \
        } while (0)

/**
 *                     |<-------- hv ------->|
 * NAME header => [ hi | length | text | '\0 ]
 *                  1    2        VAR    1
 * Size = 1 + 2 + VAR + 1
 * @name convert to UTF-16BE
 */

/**
 *                     |<-------- hv ------->|
 * TYPE header => [ hi | length | text | '\0 ]
 *                  1    2        VAR    1
 * Size = 1 + 2 + VAR + 1
 * @type reamin UTF-8
 */

/**
 *                       |<- hv ->|
 * LENGTH header => [ hi | length ]
 *                    1    4
 * Size = 1 + 4
 */

/**
 *                     |<---------- hv ------>|
 * BODY header => [ hi | length | content ... ]
 *                  1    2        VAR
 * Size = 1 + 2 + VAR
 */

/**
 *                          |<-------- hv -------->|
 * END OF BODY head => [ hi | length | content ... ]
 *                       1    2        VAR
 * Size = 1 + 2 + VAR
 *
 * @length can be set to 0,when the @content is
 * not contains valid data.
 * we can simply set hi to END OF BODY,and fill
 * the remain with zero.
 * if @content contains valid data,@length must
 * ot be zero.
 */

#endif /* obex_impl.h */
