#ifndef _OBEX_HELPERS_H_
#define _OBEX_HELPERS_H_

#include <stdio.h>

#include "obex_packet_def.h"
#include "obex_impl.h"

#include "mime_type.h"

typedef bool (*obex_status_checker_t)(obex_response_t *);

#define obex_test_res_code(__resp, __expect) ({ \
        (__resp)->packet_code == __expect;      \
        })

/* the connection success code is 0xa0 */
static inline bool obex_connect_ok(obex_response_t *res)
{
        printf("peer return %#x\n", res->packet_code);
        uint8_t expect_code = OBEX_RESC_OK;
        obex_set_final(&expect_code);
//        printf("expect code %#x\n", expect_code);
        return obex_test_res_code(res, expect_code);
}

#define obex_is_success obex_connect_ok

static inline bool obex_is_res_cont(obex_response_t *res)
{
        printf("peer return %#x\n", res->packet_code);
        uint8_t expect_code = OBEX_RESC_CONT;
        obex_set_final(&expect_code);
//        printf("expect code %#x\n", expect_code);
        return obex_test_res_code(res, expect_code);
}

/* exchange object */
extern int obex_try_connect(int obex_sock, uint8_t flags, uint16_t *packet_size);
extern int obex_send_initial_put(int obex_sock, const char *file_name, size_t file_size,
                                 void *first_chunk, size_t first_chunk_size,
                                 enum MIME_TYPE t, int all);
extern int obex_send_middle_put(int obex_sock, void *chunk, size_t chunk_size);
extern int obex_send_final_put(int obex_sock);
extern int obex_send_disconnect(int obex_sock);

#endif
