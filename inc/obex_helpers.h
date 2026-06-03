#ifndef _OBEX_HELPERS_H_
#define _OBEX_HELPERS_H_

#include <unistd.h>
#include <stddef.h>

#include "obex_packet_def.h"

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
                        __remain -= __ret;                                      \
                }                                                               \
        } while (0)

typedef bool (*obex_status_checker_t)(obex_response_t *);
extern int generic_obex_send(int, const obex_request_t *, obex_response_t *,
                             obex_status_checker_t, int);
extern bool obex_status_is_ok(obex_response_t *);
extern bool obex_status_is_cont(obex_response_t *);
extern bool obex_status_bypass(obex_response_t *);

#endif
