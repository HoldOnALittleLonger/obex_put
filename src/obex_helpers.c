#include <unistd.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "obex_packet_def.h"
#include "obex_impl.h"
#include "obex_helpers.h"
#include "obex_layout.h"

#include "mime_type.h"

/* flush opt data if has any */
#define flush_obex_stream(__obex_sock, __rest_size)                             \
        do {                                                                    \
                uint8_t trash[128] = {0};                                       \
                size_t __remain = __rest_size;                                  \
                while (__remain) {                                              \
                        size_t to_read = __remain < 128 ? __remain : 128;       \
                        ssize_t __ret = read(__obex_sock, trash, to_read);      \
                        if (__ret <= 0)                                         \
                                break;                                          \
                        __remain -= ret;                                        \
                }                                                               \
        } while (0)

void dump_mem(void *start, size_t range, const char *msg)
{
        fprintf(stderr, "[ Dump -------------------------------- ]\n");
        fprintf(stderr, "  Total %zu bytes\n", range);
        if (msg)
                fprintf(stderr, "%s -------- START\n", msg);
        uint8_t cnt = 10;
        uint8_t *mem = (uint8_t *)start;
        fprintf(stderr, "memory address start from - %#x\n", mem);
        while (range--) {
                fprintf(stderr, "%#04x ", *mem++);
                if (!--cnt){
                        putchar('\n');
                        cnt = 10;
                }
        }
        putchar('\n');
        if (msg)
                fprintf(stderr, "%s -------- END\n", msg);
        fprintf(stderr, "[ ---------------- CUT OFF ---------------- ]\n");
}

/**
 * obex_send - generic send method.
 * @obex_sock: socket
 * @put_req:   request need to send
 * @tester:    status code tester
 * @need_res:  memov response if not NULL
 * return:     0 OR -1
 * # flush additional data if has nay.
 */
static int obex_send(int obex_sock, obex_request_t *put_req,
                     obex_status_checker_t tester, obex_response_t *need_res)
{
        ssize_t ret = write(obex_sock, put_req, ntohs(put_req->packet_len_netord));
        if (ret <= 0)
                return -1;
        ctor_obex_minimal_response_local(__res);
        ret = read(obex_sock, __res, OBEX_PACKET_HDR_SIZE);
        if (ret <= 0 || !tester(__res)) {
                ret = -1;
                goto exit_err_free;
        }
        
        /* if we need res,we must flush stream manually */
        if (need_res)
                memmove(need_res, __res, ret);
        else {
                ret = ntohs(__res->packet_len_netord) - ret;
                flush_obex_stream(obex_sock, ret);
        }
        
exit_err_free:
        dtor_obex_minimal_response_local(__res);
        return ret;
}

/**
 * obex_try_connect - construct a minimal CONNECT request,and try connect
 *                    to peer.
 * @obex_sock:        socket to peer
 * @flags:            flags
 * @packet_size:      the packet size we want
 * return:            0 OR -1
 */
int obex_try_connect(int obex_sock, uint8_t flags, uint16_t *packet_size)
{
        obex_request_t *connect_req = ctor_obex_connect_request(OBEX_CURR_VERSION_NUM,
                                                                flags,
                                                                *packet_size, 0);
        if (!connect_req)
                return -1;
        
#if defined(DEBUG)
        dump_mem(connect_req, ntohs(connect_req->packet_len_netord), "dump connect request");
#endif

        uint8_t res_buffer[MIN_OBEX_PACKET_SIZE] = {0};
        obex_response_t *res = (obex_response_t *)res_buffer;
        int result = obex_send(obex_sock, connect_req, obex_connect_ok, res);
        if (result < 0)
                goto exit_err_free;
        
        /* read reamin */
        size_t readed = OBEX_PACKET_HDR_SIZE;
        size_t remain = ntohs(res->packet_len_netord) - readed;
        result = read(obex_sock, res_buffer + readed, remain);
        if (result <= 0) {
                result = -1;
                goto exit_err_free;
        }
        /* we hope version 1.0 */
        if (OBEX_CURR_VERSION_NUM != *extract_obex_conn_vern(res)) {
                perror("error: bad OBEX version.\n");
                result = -1; 
                goto exit_err_free;
        }
        
#if defined(DEBUG)
        dump_mem(res, 3, "dump connect response");
#endif
        
        *packet_size = *extract_obex_conn_maxpsize(res);
        
exit_err_free:
        dtor_obex_packet(connect_req);
        return result;
}

int obex_send_initial_put(int obex_sock, const char *file_name, size_t file_size,
                          void *first_chunk, size_t first_chunk_size, enum MIME_TYPE t,
                          int all)
                          
{
        ohdr_init_collect *collect_head, *tmp;
        int ret = 0;

#if defined(DEBUG)
        fprintf(stderr, "First PUT,mime type is %s\n", get_mime_type(t));
        fprintf(stderr, "File name is %s\n", file_name);
#endif

        /* NAME */
        struct obex_hdr_initializer v =
                ctor_obex_hdr_initializer((uint64_t)file_name, 1, 0);
        tmp = ctor_ohdr_init_collect(OBEX_HI_NAME, &v);
        if (!tmp)
                return -1;
        collect_head = tmp;

        /* TYPE */
        v = ctor_obex_hdr_initializer((uint64_t)get_mime_type(t), 1, 0);
        tmp = ctor_ohdr_init_collect(OBEX_HI_TYPE, &v);
        if (!tmp) {
                ret = -1;
                goto exit_err_free;
        }
        ohdr_init_collect_add(tmp, collect_head);

        /* LENGTH */
        v = ctor_obex_hdr_initializer(file_size, 1, 0);
        tmp = ctor_ohdr_init_collect(OBEX_HI_LENGTH, &v);
        if (!tmp) {
                ret = -1;
                goto exit_err_free;
        }
        ohdr_init_collect_add(tmp, collect_head);

        /* BODY / EOB */
        v = ctor_obex_hdr_initializer((uint64_t)first_chunk, 0, first_chunk_size);
        if (all)
                tmp = ctor_ohdr_init_collect(OBEX_HI_EOB, &v);
        else
                tmp = ctor_ohdr_init_collect(OBEX_HI_BODY, &v);
        if (!tmp) {
                ret = -1;
                goto exit_err_free;
        }
        ohdr_init_collect_add(tmp, collect_head);

        /* build packet */
        obex_request_t *put_req = obex_make_first_put_req(collect_head);
        if (!put_req) {
                ret = -1;
                goto exit_err_free;
        }
        
#if defined(DEBUG)
        dump_mem(put_req, ntohs(put_req->packet_len_netord) - first_chunk_size, "First PUT");
#endif
        
        obex_status_checker_t checker = all ? obex_is_success : obex_is_res_cont;

#if defined(DEBUG)
        ctor_obex_minimal_response_local(__res);
        ret = obex_send(obex_sock, put_req, checker, __res);
        dump_mem(__res, OBEX_PACKET_HDR_SIZE, "First PUT Response");
        dtor_obex_minimal_response_local(__res);
#else
        ret = obex_send(obex_sock, put_req, checker, NULL);
#endif
        
        dtor_obex_packet(put_req);
exit_err_free:
        destroy_whole_ohdr_init_collect(collect_head);
        return ret;
}

int obex_send_middle_put(int obex_sock, void *chunk, size_t chunk_size)
{
        struct obex_hdr_initializer v = {0};
        ohdr_init_collect *head, *tmp;
        int ret = 0;
        v = ctor_obex_hdr_initializer((uint64_t)chunk, 0, chunk_size);
        head = ctor_ohdr_init_collect(OBEX_HI_BODY, &v);
        if (!head)
                return -1;
        
#if defined(DEBUG)
        fprintf(stderr, "%s: ready to invoke obex_make_rest_put() %d\n",
                __FUNCTION__, __LINE__);
        fprintf(stderr, "chunk at %#x,size is %zu\n", chunk, chunk_size);
#endif
        
        obex_request_t *put_req = obex_make_rest_put(head);
//        obex_request_t *put_req = obex_make_first_put_req(head);
        if (!put_req) {
#if defined(DEBUG)
                fprintf(stderr, "obex_make_rest_put() returned NULL\n");
#endif
                ret = -1;
                goto exit_err_free;
        }
        
#if defined(DEBUG)
        dump_mem(put_req, ntohs(put_req->packet_len_netord) - chunk_size, "Rest PUT");
        fprintf(stderr, "Rest PUT size is %zu\n", ntohs(put_req->packet_len_netord));
#endif

#if defined(DEBUG)
        ctor_obex_minimal_response_local(__res);
        ret = obex_send(obex_sock, put_req, obex_is_res_cont, __res);
        dump_mem(__res, OBEX_PACKET_HDR_SIZE, "Rest PUT Response");
        dtor_obex_minimal_response_local(__res);
#else
        ret = obex_send(obex_sock, put_req, obex_is_res_cont, NULL);
#endif
        
        dtor_obex_packet(put_req);
exit_err_free:
        destroy_whole_ohdr_init_collect(head);
        return ret;
}

int obex_send_final_put(int obex_sock)
{
        struct obex_hdr_initializer v =
                ctor_obex_hdr_initializer(0, 0, 0);
        ohdr_init_collect *head =
                ctor_ohdr_init_collect(OBEX_HI_EOB, &v);
        if (!head)
                return -1;

        int ret = 0;
        obex_request_t *put_req = obex_make_rest_put(head);
        if (!put_req) {
                ret = -1;
                goto exit_err_free;
        }

#if defined(DEBUG)
        dump_mem(put_req, ntohs(put_req->packet_len_netord), "Final PUT");
#endif

#if defined(DEBUG)
        ctor_obex_minimal_response_local(__res);
        ret = obex_send(obex_sock, put_req, obex_is_success, __res);
        dump_mem(__res, OBEX_PACKET_HDR_SIZE, "Final PUT Response");
        dtor_obex_minimal_response_local(__res);
#else
        ret = obex_send(obex_sock, put_req, obex_is_success, NULL);
#endif
        
        dtor_obex_packet(put_req);
exit_err_free:
        destroy_whole_ohdr_init_collect(head);
        return ret;
}

int obex_send_disconnect(int obex_sock)
{
        ctor_obex_minimal_disconnect_local(__disreq);
        int result = obex_send(obex_sock, __disreq, obex_is_success, NULL);
        result = 0;
        dtor_obex_minimal_disconnect_local(__disreq);
        return result;
}

