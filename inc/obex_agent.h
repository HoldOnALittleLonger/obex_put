#ifndef _OBEX_AGENT_H_
#define _OBEX_AGENT_H_

what is agent ?

Agent,it is the thing that help us to
        rule the layout.

        file name => NAME hdr
        file size => LENGTH hdr
        file content => BODY hdr
        code => PUT
        error report => tell user what happened
        
        PUT Agent
        /        \
       /          \        
      /            \
[ | | | ----------- | ------------ ] => laytout
[ -------------------------------- ] => packet

        CONNECT Agent <= packet size we expect
                         flags,need for control

        union obex_agent_data {

                                 /* COUNT */
                                 struct {
                                         uint32_t d_count;
                                 };

                                 /* NAME */
                                 struct {
                                         const char *d_name;
                                 };

                                 /* TYPE */
                                 struct {
                                         const char *d_type;
                                 };

                                 /* LENGTH */
                                 struct {
                                         uint32_t d_length;
                                 };

                                 /* TIME */
                                 struct {
                                         const char *d_timestamp;
                                 };

                                 /* DESCRIPTION */
                                 struct {
                                         const char *d_description;
                                 };

                                 /* TARGET */
                                 struct {
                                         const char *d_target;
                                 };

                                 /* HTTP */
                                 struct {
                                         const char *d_httphdr;
                                 };

                                 /* BODY / End-Of-Body */
                                 struct {
                                         void *d_body_chunk;
                                         size_t d_body_chunk_size;
                                 };

                                 /* WHO */
                                 struct {
                                         const char *d_who;
                                 };

                                 /* CONNECT IDENTIFIER */
                                 struct {
                                         uint32_t d_connectid;
                                 };

                         };


        union obex_agent_data {
                struct {
                        uint32_t cad_count;
                        uint32_t cad_length;
                        const char *cad_who;
                        const char *cad_target;
                        const char *cad_description;
                        uint32_t cad_connectid;
                } connect_agent_data;

                struct {
                        const char *pad_name;
                        const char *pad_type;
                        uint32_t pad_length;
                        struct {
                                void *pad_chunk;
                                size_t *pad_chunk_size;
                        };
                } put_agent_data;

                struct { } get_agent_data;
        };

struct obex_cad_operations;
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

void obex_ca_get(struct obex_connect_agent *agent)
{
        agent->refcnt++;
}

void obex_ca_put(struct obex_connect_agent *agent)
{
        agent->refcnt--;
        if (!agent->refcnt)
                dtor_obex_ca(agent);
}

struct obex_connect_agent_operations {
        int (*connect)(struct obex_connect_agent *agent);
        void (*disconnect)(struct obex_connect_agent *agent);
        int (*rfcomm_socket)(struct obex_connect_agent *agent);
        uint8_t (*mod_channel)(struct obex_connect_agent *agent, uint8_t new_channel);
        const char (*mod_peer_addr)(struct obex_connect_agent *agent, const char *peer);
};

int default_obex_ca_connect(struct obex_connect_agent *agent)
{
        struct sockaddr_rc rc_addr = {
                .rc_family = AF_BLUETOOTH,
                .rc_channel = channel,
        };
        str2ba(agent->peer_bt_addr, &rc_addr.rc_bdaddr);
        agent->rfcomm_socket = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
        if (agent->rfcomm_socket < 0)
                return -EAGAIN;
        if (connect(agent->rfcomm_socket, (struct sockaddr *)&rc_addr, sizeof(rc_addr))
            < 0)
                if (errno == EINVAL)
                        return -EINVAL;
                else
                        return -EAGAIN;

        int ret = 0;
        struct obex_packet *req_packet = NULL;
        struct obex_layout_struct *layout = NULL;
        const struct obex_cad_operations *cadops = agent->cad_ops;
        uint8_t mini_connect_packet[OBEX_MINI_CONNECTREQ_SIZE] = {0};
        uint8_t res_buff[MIN_OBEX_PACKET_SIZE] = {0};
        
        req_packet = (struct obex_packet *)mini_connect_packet;
        if (cadops->zeroed_out(&agent->cad)) {
                /* fast path */
                copy_obex_mini_connect(agent->flags, agent->mpsize,
                                       req_packet, OBEX_MINI_CONNECTREQ_SIZE);
                ret = generic_obex_send(agent->rfcomm_sock, req_packet, res_buff);
        }
        else {
                /* slow path */
                ohdr_init_collect *hdrs = NULL;
                ret = -ENOMEM;
                layout = ctor_obex_layout();
                if (!layout)
                        goto exit_err_close;

                hdrs = cadops->to_hdrs(&agent->cad);
                if (!hdrs)
                        goto exit_put_layout;

                const struct obex_layout_ops *lops = layout->lops;
                ret = lops->make_packet(layout, hdrs);
                destroy_whole_ohdr_init_collect(hdrs);
                if (ret < 0) {
                        ret = -ENOMEM;
                        goto exit_put_layout;
                }
                
                req_packet = lops->get_packet(layout);
                ret = generic_obex_send(agent->rfcomm_sock, req_packet, res_buff);
                lops->put_packet(layout);
        }

        /* result of generic obex send */
        if (ret < 0) {
                ret = -EBUSY;
        } else {
                /* we need remaining data to determine version and packet size */
                obex_response_t *res = (obex_response_t *)res_buff;
                size_t remain = ntohs(res->packet_len_netord) - OBEX_PACKET_HDR_SIZE;
                remain = read(agent->rfcomm_sock, res_buff + OBEX_PACKET_HDR_SIZE, remain);
                if (remain <= 0) {
                        ret = -EIO;
                        goto exit_destroy_hdrs;
                }

                if (OBEX_CURR_VERSION_NUM != *obex_connect_vern(res)) {
                        ret = -EINVAL;
                        goto exit_destroy_hdrs;
                }
                agent->packet_size = *obex_connect_mpsize(res);
                agent->connected = 1;
                ret = 0;
        }

exit_put_layout:
        if (layout)
                put_layout(layout);

exit_err_close:
        if (!agent->connected) {
                (void)shutdown(agent->rfcomm_sock, SHUT_RDWR);
                agent->rfcomm_sock = -1;
        }
        return ret;
}




//                                 /* COUNT */
//                                 struct {
//                                         uint32_t d_count;
//                                 };
//
//                                 /* NAME */
//                                 struct {
//                                         const char *d_name;
//                                 };
//
//                                 /* TYPE */
//                                 struct {
//                                         const char *d_type;
//                                 };
//
//                                 /* LENGTH */
//                                 struct {
//                                         uint32_t d_length;
//                                 };
//
//                                 /* TIME */
//                                 struct {
//                                         const char *d_timestamp;
//                                 };
//
//                                 /* DESCRIPTION */
//                                 struct {
//                                         const char *d_description;
//                                 };
//
//                                 /* TARGET */
//                                 struct {
//                                         const char *d_target;
//                                 };
//
//                                 /* HTTP */
//                                 struct {
//                                         const char *d_httphdr;
//                                 };
//
//                                 /* BODY / End-Of-Body */
//                                 struct {
//                                         void *d_body_chunk;
//                                         size_t d_body_chunk_size;
//                                 };
//
//                                 /* WHO */
//                                 struct {
//                                         const char *d_who;
//                                 };
//
//                                 /* CONNECT IDENTIFIER */
//                                 struct {
//                                         uint32_t d_connectid;
//                                 };

                         };


        struct obex_agent_data {


                         };

struct obex_connect_agent {
        struct obex_agent_data agent_data;
        
};
                         


#endif /* obex_agent.h */
