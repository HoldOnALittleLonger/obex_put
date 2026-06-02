#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#include "obex_helpers.h"
#include "obex_impl.h"

/**
 * generic_obex_send - generic send method.
 * @obex_sock:         socket
 * @req:               request need to send
 * @res:               where to store response
 * @tester:            check whether peer returned good msg
 * return:             0 OR error code
 * # -EINVAL  => !@res
 *   -EIO     => write / read failed
 *   -EBADMSG => checking failed
 */

int generic_obex_send(int obex_sock, const obex_request_t *req, obex_response_t *res,
                      obex_status_checker_t tester)
{
        ssize_t ret = 0;
        if (!res)
                return -EINVAL;
        ret = write(obex_sock, req, ntohs(req->packet_len_netord));
        if (ret <= 0)
                return -EIO;
        ret = read(obex_sock, res, OBEX_PACKET_HDR_SIZE);
        if (ret <= 0)
                return -EIO;

        if (!tester(res))
                return -EBADMSG;
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
