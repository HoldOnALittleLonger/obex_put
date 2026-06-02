#define UM_CONFIG_DUMP

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>

#include "obex_agent.h"
#include "obex_layout.h"
#include "obex_helpers.h"
#include "obex_impl.h"

#include <arpa/inet.h>

#include "utility_macro.h"

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
        uint8_t res_buff[MIN_OBEX_PACKET_SIZE] = {0};

        req_packet = (struct obex_packet *)mini_connect_packet;
        if (minimal) {
                /* fast path */
                copy_obex_mini_connect(agent->flags, agent->packet_size,
                                       req_packet, OBEX_MINI_CONNECTREQ_SIZE);
                ret = generic_obex_send(socketfd, req_packet, (obex_request_t *)res_buff, obex_status_is_ok);
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
                        ret = -ENOMEM;
                        goto failed_put_layout;
                }

                ret = lops->make_packet(layout, OBEX_REQC_CONNECT, hdrs);
                /* after we built packet,we can destroy hdrs */
                cadops->destroy_hdrs(hdrs);
                if (ret < 0) {
                        ret = -ENOMEM;
                        goto failed_put_layout;
                }
                
                req_packet = lops->get_packet_mutable(layout);
                ret = generic_obex_send(socketfd, req_packet, (obex_request_t *)res_buff, obex_status_is_ok);
                lops->put_packet(layout);
                
        failed_put_layout:
                dtor_obex_layout(layout);
        }

        /* result of generic obex send */
        if (ret < 0)
                ret = (ret != -ENOMEM) ? -EBUSY : ret;
        else {
                /* we need remaining data to determine version and packet size */
                obex_response_t *res = (obex_response_t *)res_buff;
                size_t remain = ntohs(res->packet_len_netord) - OBEX_PACKET_HDR_SIZE;
                remain = read(socketfd, res_buff + OBEX_PACKET_HDR_SIZE, remain);
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
                agent->packet_size = *obex_connect_mpsize(res);
                agent->connected = 1;
                ret = 0;
        }

exit_err_close:
        if (!agent->connected)
                (void)shutdown(socketfd, SHUT_RDWR);
        return ret;
}

/* send disconnect request to obex server,disconnect rfcomm socket */
static void default_ca_disconnect(struct obex_connect_agent *agent)
{
        /* not connected been */
        if (!agent->connected)
                return;

        uint8_t mini_res[OBEX_PACKET_HDR_SIZE] = {0};
        ctor_obex_minimal_disconnect_local(disconnect_req);
        generic_obex_send(agent->rfcomm_socket, disconnect_req, (obex_request_t *)mini_res, obex_status_bypass);
        shutdown(agent->rfcomm_socket, SHUT_RDWR);
        agent->rfcomm_socket = -1;
        agent->connected = 0;
        dtor_obex_minimal_disconnect_local(disconnect_req);
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
        .mod_channel = default_ca_mod_channel,
        .mod_peer_addr = default_ca_mod_peer_addr,
};

/* ctor to connect agent */
struct obex_connect_agent *ctor_obex_ca(const char *bt_addr, uint8_t channel,
                                        uint8_t flags, uint16_t packet_size)
{
        struct obex_connect_agent *agent = malloc(sizeof(struct obex_connect_agent));
        if (agent) {
                agent->peer_bt_addr = bt_addr;
                agent->packet_size = packet_size;
                agent->service_channel = channel;
                agent->flags = flags;
                agent->rfcomm_socket = -1;
                agent->refcnt = 1;
                agent->connected = 0;
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
        if (agent->fd_user)
                return -EBUSY;
        agent->registered_fd = fd;
        return 0;
}

static int default_pa_register_rfcommsock(struct obex_put_agent *agent, int fd)
{
        if (agent->fd_user)
                return -EBUSY;
        agent->registered_rfcommsock = fd;
        return 0;
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

        /**
         * RCU read-side start point.
         * We now dont think of multithread.
         */
        agent->fd_user++;
        socket_fd = agent->registered_rfcommsock;
        fd = agent->registered_fd;
        agent->fd_user--;
        
        if (socket_fd < 0 || fd < 0)
                return -EIO;

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
                        padops->mod_connectid(pad, 0);
                        padops->mod_name(pad, NULL);
                        padops->mod_type(pad, NULL);
                        padops->mod_length(pad, 0);
                        remove_useless_pad = 1;
                }
                ret = lops->make_packet(layout, OBEX_REQC_PUT, hdrs);
                padops->destroy_all_hdrs(hdrs);
                packet = lops->get_packet(layout);
                um_dump_mem(packet, 64, NULL);
                ret = generic_obex_send(socket_fd, packet, res, obex_status_is_cont);
                lops->put_packet(layout);
                agent->status_code = res->packet_code;
                if (ret < 0)
                        goto exit_put_layout;

        } while (1);

        const obex_request_t *eob_packet = (const obex_request_t *)obex_mini_eob_req;
        ret = generic_obex_send(socket_fd, eob_packet, res, obex_status_is_ok);
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

const struct obex_put_agent_operations default_pa_ops = {
        .register_fd = default_pa_register_fd,
        .register_rfcommsock = default_pa_register_rfcommsock,
        .push_object = default_pa_push_object,
};

struct obex_put_agent *ctor_obex_pa(void)
{
        struct obex_put_agent *pa = malloc(sizeof(struct obex_put_agent));
        if (pa) {
                pa->registered_fd = -1;
                pa->registered_rfcommsock = -1;
                pa->status_code = 0;
                pa->fd_user = 0;
                pa->refcnt = 1;
                pa->pa_ops = &default_pa_ops;
                pa->pad_ops = &default_obex_pad_ops;
                union obex_agent_data tmp = {0};
                pa->pad = tmp;
        }
        return pa;
}

