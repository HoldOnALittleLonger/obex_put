#define _GNU_SOURCE

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#include "obex_agent.h"
#include "obex_layout.h"
#include "obex_helpers.h"
#include "obex_impl.h"

/**
 * =============
 * CONNECT Agent
 * =============
 */

/**
 * default_ca_connect - default connect operation
 * # we will open socket at there
 */
static int default_ca_connect(struct obex_connect_agent *agent, int minimal)
{
        int ret = 0;
        int socketfd = -1;
        uint8_t channel = agent->service_channel;
        struct sockaddr_rc rc_addr = {
                .rc_family = AF_BLUETOOTH,
                .rc_channel = channel,
        };
        str2ba(agent->peer_bt_addr, &rc_addr.rc_bdaddr);
        socketfd = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
        if (socketfd < 0)
                return -EAGAIN;
        if (connect(socketfd, (struct sockaddr *)&rc_addr,
                    sizeof(rc_addr)) < 0) {
                ret = -EFAULT;
                goto exit_err_close;
        }

        struct obex_packet *req_packet = NULL;
        const struct obex_cad_operations *cadops = agent->cad_ops;
        uint8_t mini_connect_packet[OBEX_MINI_CONNECTREQ_SIZE] = {0};

        #define RES_BUFF_SIZE 128
        uint8_t res_buff[RES_BUFF_SIZE] = {0};        

        req_packet = (struct obex_packet *)mini_connect_packet;
        if (minimal) {
                /* fast path */
                copy_obex_mini_connect(agent->flags, agent->mtu,
                                       req_packet, OBEX_MINI_CONNECTREQ_SIZE);
                ret = generic_obex_send(socketfd, req_packet, (obex_request_t *)res_buff, obex_status_is_ok, 0);
        }
        else {
                /* slow path */
                struct obex_layout_struct *layout = NULL;
                ohdr_init_collect *hdrs = NULL;
                const struct obex_layout_operations *lops = NULL;
                
                layout = ctor_obex_layout();
                if (!layout)
                        goto exit_err_close;
                lops = layout->lops;

                hdrs = cadops->to_hdrs(&agent->cad);
                if (!hdrs) {
                        ret = -EFAULT;
                        goto failed_put_layout;
                }

                ret = lops->make_packet(layout, OBEX_REQC_CONNECT, hdrs);
                /* after we built packet,we can destroy hdrs */
                cadops->destroy_hdrs(hdrs);
                if (ret < 0)
                        goto failed_put_layout;

                req_packet = lops->get_packet_mutable(layout);
                ret = generic_obex_send(socketfd, req_packet, (obex_request_t *)res_buff, obex_status_is_ok, 0);
                lops->put_packet(layout);
                
        failed_put_layout:
                dtor_obex_layout(layout);
        }

        /* obex send connect request got OK */
        if (!ret) {
                /**
                 * we need the remaining data to determine version and packet size.
                 * maybe there are options returned by peer,but we ignore them currently.
                 */
                obex_response_t *res = (obex_response_t *)res_buff;
                const size_t pkg_size = ntohs(res->packet_len_netord);
                
                /* generic_obex_send() always reads response data with
                 * OBEX_PACKET_HDR_SIZE bytes when @flush_stream is 0.
                 */
                const size_t received_size = OBEX_PACKET_HDR_SIZE;
                
                const size_t left_space = RES_BUFF_SIZE - received_size;
                /* prevent exceed buffer boundary */
                size_t remain = (pkg_size - received_size) > left_space ? left_space :
                        pkg_size - received_size;
                
                remain = recv(socketfd, res_buff + received_size, remain, 0);
                if (remain <= 0) {
                        ret = -EIO;
                        goto exit_err_close;
                }

                if (OBEX_CURR_VERSION_NUM != *obex_connect_vern(res)) {
                        ret = -EINVAL;
                        goto exit_err_close;
                }

                /* connected */
                agent->rfcomm_socket = socketfd;
                agent->mtu = *obex_connect_mpsize(res);
                agent->connected = 1;
                ret = 0;
        }

exit_err_close:
        if (!agent->connected)
                (void)shutdown(socketfd, SHUT_RDWR);
        return ret;

        #undef RES_BUFF_SIZE
}

/* send disconnect request to obex server,disconnect rfcomm socket */
static void default_ca_disconnect(struct obex_connect_agent *agent)
{
        /* not connected been */
        if (!agent->connected)
                return;

        uint8_t mini_res[OBEX_PACKET_HDR_SIZE] = {0};
        ctor_obex_minimal_disconnect_local(disconnect_req);
        generic_obex_send(agent->rfcomm_socket, disconnect_req, (obex_request_t *)mini_res, obex_status_bypass, 0);
        shutdown(agent->rfcomm_socket, SHUT_RDWR);
        agent->rfcomm_socket = -1;
        agent->connected = 0;
        dtor_obex_minimal_disconnect_local(disconnect_req);
}

int default_ca_attach(struct obex_connect_agent *agent, void *op)
{
        if (agent->attached)
                return -EBUSY;

        agent->attached = 1;
        agent->private = op;
        return 0;
}

int default_ca_deattach(struct obex_connect_agent *agent)
{
        if (!agent->attached)
                return -EINVAL;
        agent->attached = 0;
        agent->private = NULL;
        return 0;
}

static int default_ca_mod_channel(struct obex_connect_agent *agent, uint8_t new_channel)
{
        if (agent->connected)
                return -EBUSY;
        
        if (!new_channel || new_channel > BLUETOOTH_RFCOMM_CHANNEL_MAX)
                return -EINVAL;
        agent->service_channel = new_channel;
        return 0;
}

/**
 * mod_peer_addr - default op to modify peer's address string,
 *                 will return -EBUSY if been connected.
 */
static int default_ca_mod_peer_addr(struct obex_connect_agent *agent,
                                    const char *peer)
{
        if (agent->connected)
                return -EBUSY;
        agent->peer_bt_addr = peer;
        return 0;
}

/* default ca ops */
const struct obex_connect_agent_operations default_obex_ca_ops = {
        .connect = default_ca_connect,
        .disconnect = default_ca_disconnect,
        .attach = default_ca_attach,
        .deattach = default_ca_deattach,
        .mod_channel = default_ca_mod_channel,
        .mod_peer_addr = default_ca_mod_peer_addr,
};

/* ctor to connect agent */
struct obex_connect_agent *ctor_obex_ca(const char *bt_addr, uint8_t channel,
                                        uint8_t flags, uint16_t mtu)
{
        struct obex_connect_agent *agent = malloc(sizeof(struct obex_connect_agent));
        if (agent) {
                agent->peer_bt_addr = bt_addr;
                agent->mtu = mtu;
                agent->service_channel = channel;
                agent->flags = flags;
                agent->rfcomm_socket = -1;
                agent->connected = 0;
                agent->attached = 0;
                agent->private = NULL;
                agent->ca_ops = &default_obex_ca_ops;
                agent->cad_ops = &default_obex_cad_ops;

                union obex_agent_data tmp = {0};
                agent->cad = tmp;
        }
        return agent;
}

/**
 * =========
 * PUT Agent
 * =========
 */
static int default_pa_register_fd(struct obex_put_agent *agent, int fd)
{
        int old = agent->registered_fd;
        agent->registered_fd = fd;
        return old;
}

static int default_pa_push_object(struct obex_put_agent *agent)
{
        int ret = 0;
        uint8_t res_buffer[OBEX_PACKET_HDR_SIZE] = {0};
        obex_response_t *res = (obex_response_t *)res_buffer;
        const struct obex_put_agent_operations *paops = agent->pa_ops;
        const struct obex_pad_operations *padops = agent->pad_ops;
        union obex_agent_data *pad = &agent->pad;
        struct obex_layout_struct *layout = NULL;
        const struct obex_layout_operations *lops = NULL;
        const struct obex_packet *packet = NULL;
        void *chunk = NULL;
        size_t chunk_size = padops->mod_chunk_size(pad, 0);
        int socket_fd = -1, fd = -1;

        if (!agent->residing)
                return -ENODEV;

        fd = agent->registered_fd;
        socket_fd = agent->residing->rfcomm_socket;
        
        if (socket_fd < 0 || fd < 0)
                return -EIO;

        /* we advise kernel sequential reading on @fd */
        assert(posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL) == 0);

        ret = -ENOMEM;
        chunk = malloc(sizeof(uint8_t) * chunk_size);
        if (!chunk)
                goto exit_err;
        /* setup chunk info */
        padops->mod_chunk(pad, chunk);

        layout = ctor_obex_layout();
        if (!layout)
                goto exit_free;
        lops = layout->lops;

        int remove_useless_pad = 0;
        do {
                /* read file and send */
                
                ssize_t readed = read(fd, chunk, chunk_size);
                if (readed < 0) {
                        ret = -EIO;
                        goto exit_put_layout;
                } else if (!readed) /* EOF */
                        break;
                padops->mod_chunk_size(pad, readed);

                ohdr_init_collect *hdrs = padops->to_hdrs(pad);
                if (!hdrs)
                        goto exit_put_layout;
                else if (!remove_useless_pad) {
                        padops->mod_name(pad, NULL);
                        padops->mod_length(pad, 0);
                        padops->mod_type(pad, NULL);
                        remove_useless_pad = 1;
                }

                ret = lops->make_packet(layout, OBEX_REQC_PUT, hdrs);
                padops->destroy_hdrs(hdrs);
                packet = lops->get_packet(layout);
                ret = generic_obex_send(socket_fd, packet, res, obex_status_is_cont, 1);
                lops->put_packet(layout);
                agent->status_code = res->packet_code;
                if (ret < 0)
                        goto exit_put_layout;

        } while (1);

        const obex_request_t *eob_packet = (const obex_request_t *)obex_mini_eob_req;
        ret = generic_obex_send(socket_fd, eob_packet, res, obex_status_is_ok, 1);
        agent->status_code = res->packet_code;
        if (ret < 0)
                ret = -EIO;

exit_put_layout:
        put_layout(layout);
        
exit_free:
        free(chunk);

exit_err:
        return ret;
}

static int default_pa_reside_on(struct obex_put_agent *agent, struct obex_connect_agent *cagent)
{
        int ret = 0;
        const struct obex_connect_agent_operations *caops = NULL;
        if (agent->residing)
                return -EINVAL;
        caops = cagent->ca_ops;
        caops->attach(cagent, agent);
        agent->residing = cagent;
        return 0;
}

static int default_pa_go_away(struct obex_put_agent *agent)
{
        struct obex_connect_agent *cagent = agent->residing;
        const struct obex_connect_agent_operations *caops = NULL;
        int ret = 0;

        if (!cagent)
                return -EINVAL;
        caops = cagent->ca_ops;
        ret = caops->deattach(cagent);
        if (ret < 0)
                return ret;
        agent->residing = NULL;
        return 0;
}

const struct obex_put_agent_operations default_pa_ops = {
        .register_fd = default_pa_register_fd,
        .push_object = default_pa_push_object,
        .reside_on = default_pa_reside_on,
        .go_away = default_pa_go_away,
};

struct obex_put_agent *ctor_obex_pa(void)
{
        struct obex_put_agent *pa = malloc(sizeof(struct obex_put_agent));
        if (pa) {
                pa->registered_fd = -1;
                pa->status_code = 0;
                pa->residing = NULL;
                pa->pa_ops = &default_pa_ops;
                pa->pad_ops = &default_obex_pad_ops;
                union obex_agent_data tmp = {0};
                pa->pad = tmp;
        }
        return pa;
}

