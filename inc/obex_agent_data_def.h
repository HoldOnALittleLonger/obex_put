#ifndef _OBEX_AGENT_DATA_H_
#define _OBEX_AGENT_DATA_H_

#include "obex_impl.h"

union obex_agent_data {
        struct {
                uint32_t cad_connectid;
                uint32_t cad_count;
                uint32_t cad_length;
                const char *cad_who;
                const char *cad_target;
                const char *cad_description;
        }; /* connect_agent_data */

        struct {
                uint32_t pad_connectid;
                const char *pad_name;
                const char *pad_type;
                uint32_t pad_length;
                struct {
                        void *pad_chunk;
                        size_t pad_chunk_size;
                };
        }; /* put_agent_data */

        /* Others are un-implemented */
};

/**
 * Assertion: all mod_* routine will returns the old value.
 *            if the value is not valid to the specified
 *            operation,that should be reported by handler,
 *            not these operations.
 * Assertion: to_hdrs() routine guarantees the _head_ hdrs will
 *            contains valid initializer,or NULL if failed.
 */
struct obex_cad_operations {
        uint32_t (*mod_count)(union obex_agent_data *, uint32_t);
        uint32_t (*mod_length)(union obex_agent_data *, uint32_t);
        const char *(*mod_who)(union obex_agent_data *,const char *);
        const char *(*mod_target)(union obex_agent_data *,const char *);
        const char *(*mod_description)(union obex_agent_data *,const char *);
        uint32_t (*mod_connectid)(union obex_agent_data *,uint32_t);
        ohdr_init_collect *(*to_hdrs)(union obex_agent_data *);
        void (*destroy_hdrs)(ohdr_init_collect *);
};
struct obex_pad_operations {
        uint32_t (*mod_connectid)(union obex_agent_data *,uint32_t);
        const char *(*mod_name)(union obex_agent_data *, const char *);
        const char *(*mod_type)(union obex_agent_data *, const char *);
        uint32_t (*mod_length)(union obex_agent_data *, uint32_t);
        void *(*mod_chunk)(union obex_agent_data *, void *);
        size_t (*mod_chunk_size)(union obex_agent_data *, size_t);
        ohdr_init_collect *(*to_hdrs)(union obex_agent_data *);
        void (*destroy_all_hdrs)(ohdr_init_collect *);
};

extern const struct obex_cad_operations default_obex_cad_ops;
extern const struct obex_pad_operations default_obex_pad_ops;

#endif /* obex_agent_data.h */
