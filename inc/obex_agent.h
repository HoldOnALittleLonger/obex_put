/**
 * This header contains definitions of OBEX Agents.
 * An agent is an object which will does specified
 * work for us,such make a connection,send file,etc.
 * The Agent describes how the packet layout is
 * composied.
 * We usually do not need all hdrs included into
 * the packet.
 * Any agent except connection agent,needs to
 * attach a connection agent before start its work.
 * If no network stream is available,the work that
 * taken charge by that agent would not get processing.
 *
 *     file name => NAME hdr
 *     file size => LENGTH hdr
 *     type string => mime type string
 *     file content => BODY hdr
 *     code => PUT
 *     error report => return -errcode
 *      
 *      PUT Agent
 *      /        \
 *     /          \        
 *    /            \
 * [ | | | ----------- | ------------ ] => laytout
 * [ -------------------------------- ] => packet
 *
 *       CONNECT Agent <= packet size we expect
 *                        flags,need for control
 */
#ifndef _OBEX_AGENT_H_
#define _OBEX_AGENT_H_

#include <assert.h>

#include "obex_agent_data_def.h"

/**
 * =============
 * CONNECT Agent
 * =============
 */

/* the maximum number of rfcomm channel(include) */
#define BLUETOOTH_RFCOMM_CHANNEL_MAX 30
struct obex_connect_agent_operations;

/**
 * obex_connect_agent - the agent handles CONNECT establish
 * @peer_bt_addr:       peer's bluetooth address
 * @mtu:                MTU
 * @service_channel:    service rfcomm channel
 * @connected:          connect indicator
 * @attached:           whether been attached to an operation
 * @private:            private data,for a been attached connection,
 *                      this should points to the operation
 *                      descriptor
 * @ca_ops:             connect agent operations
 * @cad_ops:            connect agent data operations
 * @cad:                connect agent data
 */
struct obex_connect_agent {
        const char *peer_bt_addr;
        uint16_t mtu;
        uint8_t service_channel;
        uint8_t flags;
        
        int rfcomm_socket;
        int connected;
        
        int attached;
        void *private;
        
        const struct obex_connect_agent_operations *ca_ops;
        const struct obex_cad_operations *cad_ops;
        
        union obex_agent_data cad;
};

/**
 * ctor_obex_ca - constructor to connection agent
 * @bt_addr:      pointer to peer's bluetooth address
 * @channel:      rfcomm channel
 * @flags:        connection flags
 * @mtu:          packet size in connection request
 */
extern struct obex_connect_agent *ctor_obex_ca(const char *bt_addr, uint8_t channel,
                                               uint8_t flags, uint16_t mtu);

/**
 * dtor_obex_ca - destructor to connection agent,we can not destroy
 *                the connection when it is in-use
 * # destructor would not sends DISCONNECT request.
 */
static inline void dtor_obex_ca(struct obex_connect_agent *agent)
{
        assert(!agent->attached);
        if (agent->rfcomm_socket)
                (void)shutdown(agent->rfcomm_socket, SHUT_RDWR);
        free(agent);
}

/**
 * reference counter is useless for this model,because an operation
 * usually works on a given rfcomm channel.for other service,
 * that will requires different rfcomm channel,share connection
 * between them has no sense.
 */
/*
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
*/

struct obex_connect_agent_operations {
        int (*connect)(struct obex_connect_agent *agent, int minimal);
        void (*disconnect)(struct obex_connect_agent *agent);
        int (*attach)(struct obex_connect_agent *agent, void *op);
        int (*deattach)(struct obex_connect_agent *agent);
        int (*mod_channel)(struct obex_connect_agent *agent, uint8_t new_channel);
        int (*mod_peer_addr)(struct obex_connect_agent *agent, const char *peer);
};

/**
 * =========
 * PUT Agent
 * =========
 */

struct obex_put_agent_operations;

/**
 * obex_put_agent - an agent that handles file transferring
 * @regitered_fd:   fiel descriptor
 * @status_code:    last status code
 * @residing:       the connection it residing on
 * @pa_ops:         put agent operations
 * @pad_ops:        put agent data operations
 * @pad:            put agent data
 */
struct obex_put_agent {
        int registered_fd;
        uint8_t status_code;
        struct obex_connect_agent *residing;

        const struct obex_put_agent_operations *pa_ops;
        const struct obex_pad_operations *pad_ops;

        union obex_agent_data pad;
};

/**
 * ctor_obex_pa - constructor to put agent,it requires
 *                no parameters,because its setting
 *                relies on put agent data,and fd
 *                registering routine
 */
extern struct obex_put_agent *ctor_obex_pa(void);

/**
 * for keep consistency,we do not requires destructor
 * does deattach automatically.we should deattach manually
 * then destroy this put agent.follow this fashion,the
 * connection agent will can be destructed by call to
 * its destructor,correspons to the calling of its
 * constructor.
 */
static inline void dtor_obex_pa(struct obex_put_agent *pa)
{
        assert(!pa->residing);
        free(pa);
}

/*
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
*/

struct obex_put_agent_operations {
        int (*register_fd)(struct obex_put_agent *agent, int fd);
        int (*push_object)(struct obex_put_agent *agent);
        int (*reside_on)(struct obex_put_agent *agent, struct obex_connect_agent *cagent);
        int (*go_away)(struct obex_put_agent *agent);
};

#endif /* obex_agent.h */
