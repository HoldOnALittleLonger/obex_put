#define UM_CONFIG_LIKELY

#ifdef DEBUG

#define UM_CONFIG_DUMP

#endif

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include "obex_helpers.h"
#include "obex_impl.h"
#include "obex_layout.h"

/**
 * generic_obex_send - generic send method.
 * @obex_sock:         socket
 * @req:               request need to send
 * @res:               where to store response
 * @tester:            check whether peer returned good msg
 * return:             0 OR error code
 * # -EINVAL  => !@res OR zero size request
 *   -EIO     => write / read failed
 *   -EBADMSG => checking failed
 */

int generic_obex_send(int obex_sock, const obex_request_t *req, obex_response_t *res,
                      obex_status_checker_t tester, int flush_stream)
{
        ssize_t ret = 0;
        ssize_t send_remain_size = ntohs(req->packet_len_netord);
        if (!res || um_unlikely(send_remain_size == 0))
                return -EINVAL;

        #ifdef DEBUG
        fprintf(stderr, "in function %s :\n"
                "\tsocket - %d bytes to send - %d\n"
                "\trequest_packet address - %p flush stream? - %d\n",
                __FUNCTION__,
                obex_sock, send_remain_size,
                req, flush_stream);
        um_dump_mem(req, send_remain_size > 128 ? 128 : send_remain_size, __FUNCTION__);
        #endif

        const void *iter = req;
        while (send_remain_size > 0) {
                ret = send(obex_sock, iter, send_remain_size, 0);
                if (ret <= 0)
                        return -EIO;

                /* advance */
                iter += ret;
                send_remain_size -= ret;
        }
        ret = recv(obex_sock, res, OBEX_PACKET_HDR_SIZE, 0);
        if (um_unlikely(ret <= 0))
                return -EIO;
        if (!tester(res))
                return -EBADMSG;

        /**
         * We need to flush stream to drop the data we do not care about.
         * This is important,if we didnt,the behavior may weird.
         * When PUT is send,the send PUT message will get 0xcb,but that
         * error status is not means we really less LENGTH header.(sometimes,right)
         * Because we did not flush the stream,thus receiver will packet data
         * that mixed with the old data.
         * We can dump memory in User Mode,but all thing seems like OK,but
         * in Kernel Mode,that is not good.
         */
        if (flush_stream) {
                uint16_t rest_size = *(uint16_t *)((uint8_t *)res + 1);
                rest_size = ntohs(rest_size);
                rest_size -= ret;
                flush_obex_stream(obex_sock, rest_size);
        }
        
        return 0;
}

bool obex_status_is_ok(obex_response_t *res)
{
        uint8_t expect = OBEX_RESC_OK;
        obex_set_final(&expect);
        return res->packet_code == expect;
}

bool obex_status_is_cont(obex_response_t *res)
{
        uint8_t expect = OBEX_RESC_CONT;
        obex_set_final(&expect);
        return res->packet_code == expect;
}

bool obex_status_bypass(obex_response_t *unused)
{
        return true;
}
