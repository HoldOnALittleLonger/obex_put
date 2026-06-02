#ifndef _OBEX_AGENT_H_
#define _OBEX_AGENT_H_

/**
 * what is agent ?
 * Agent,it is the thing that help us to
 * rule the layout.
 *     file name => NAME hdr
 *     file size => LENGTH hdr
 *     file content => BODY hdr
 *     code => PUT
 *     error report => tell user what happened
 *      
 *      PUT Agent
 *      /        \
 *     /          \        
 *    /            \
 * [ | | | ----------- | ------------ ] => laytout
 * [ -------------------------------- ] => packet
 *
 *
 *       CONNECT Agent <= packet size we expect
 *                        flags,need for control
 */

#include "obex_agent_data_def.h"
/**
 * =============
 * CONNECT Agent
 * =============
 */
#define BLUETOOTH_RFCOMM_CHANNEL_MAX 30
struct obex_connect_agent_operations;
struct obex_connect_agent {
        const char *peer_bt_addr;
        uint16_t packet_size;
        uint8_t service_channel;
        uint8_t flags;
        int rfcomm_socket;
        int refcnt;
        int connected;
        
        const struct obex_connect_agent_operations *ca_ops;
        const struct obex_cad_operations *cad_ops;
        
        union obex_agent_data cad;
};
extern struct obex_connect_agent *ctor_obex_ca(const char *bt_addr, uint8_t channel,
                                               uint8_t flags, uint16_t packet_size);

static inline void dtor_obex_ca(struct obex_connect_agent *agent)
{
        if (agent->rfcomm_socket)
                (void)shutdown(agent->rfcomm_socket, SHUT_RDWR);
        free(agent);
}

static inline void obex_ca_get(struct obex_connect_agent *agent)
{
        agent->refcnt++;
}

static inline void obex_ca_put(struct obex_connect_agent *agent)
{
        agent->refcnt--;
        if (!agent->refcnt)
                dtor_obex_ca(agent);

}

struct obex_connect_agent_operations {
        int (*connect)(struct obex_connect_agent *agent, int minimal);
        void (*disconnect)(struct obex_connect_agent *agent);
        int (*mod_channel)(struct obex_connect_agent *agent, uint8_t new_channel);
        int (*mod_peer_addr)(struct obex_connect_agent *agent, const char *peer);
};

/**
 * =========
 * PUT Agent
 * =========
 */
struct obex_put_agent_operations;
struct obex_put_agent {
        int registered_fd;
        int registered_rfcommsock;
        uint8_t status_code;
        uint8_t fd_user;
        int refcnt;

        const struct obex_put_agent_operations *pa_ops;
        const struct obex_pad_operations *pad_ops;

        union obex_agent_data pad;
};

extern struct obex_put_agent *ctor_obex_pa(void);

static inline void dtor_obex_pa(struct obex_put_agent *pa)
{
        free(pa);
}

static inline void obex_pa_get(struct obex_put_agent *pa)
{
        pa->refcnt++;
}

static inline void obex_pa_put(struct obex_put_agent *pa)
{
        pa->refcnt--;
        if (!pa->refcnt)
                dtor_obex_pa(pa);
}

struct obex_put_agent_operations {
        int (*register_fd)(struct obex_put_agent *agent, int fd);
        int (*register_rfcommsock)(struct obex_put_agent *agent, int fd);
        int (*push_object)(struct obex_put_agent *agent);
};

#endif /* obex_agent.h */
