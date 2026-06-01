#ifndef _OBEX_PACKET_H_
#define _OBEX_PACKET_H_

#include <stdint.h>

/* number of objects */
#define OBEX_HI_COUNT             0xc0
/* name of object */
#define OBEX_HI_NAME              0x01
/* type of object,no type specified,binary */
#define OBEX_HI_TYPE              0x42
/* length of object in bytes */
#define OBEX_HI_LENGTH            0xc3

enum {
        /* data/time stamp iso 8601 */
        OBEX_HI_TIME_ISO8601    = 0x44,
        /* data/time stamp 4 byte version */
        OBEX_HI_TIME_4B         = 0xc4
};

/* text description of object */
#define OBEX_HI_DESCRIPTION       0x05
/* name of service that operation is targeted to */
#define OBEX_HI_TARGET            0x46
/* an HTTP 1.x header */
#define OBEX_HI_HTTP              0x47
/* a chunk of the object body */
/* a body message consists HI,2 bytes header length,
 * all or part contents of object itself
 */
#define OBEX_HI_BODY              0x48
/* the final chunk of the object body */
#define OBEX_HI_EOB               0x49
/* identifies the OBEX application */
#define OBEX_HI_WHO               0x4a
/* an identifier used for OBEX connection */
#define OBEX_HI_CONNECTID         0xcb
/* extended application request & response information */
#define OBEX_HI_APP_PARAMS        0x4c
/* authentication digest-challenge */
#define OBEX_HI_AUTH_CHALLENGE    0x4d
/* authentication digest-response */
#define OBEX_HI_AUTH_RESPONSE     0x4e
/* indicates the creator of an object */
#define OBEX_HI_CREATORID         0xcf
/* uniquely identifies the network client(OBEX server) */
#define OBEX_HI_WAN_UUID          0x50
/* OBEX Object class of object */
#define OBEX_HI_OBJCLASS          0x51
/* parameters used in session commands/reponses */
#define OBEX_HI_SESSION_PARAM     0x52
/* sequence number used in each OBEX packet for reliability */
#define OBEX_HI_SESSION_SEQNUM    0x93
/* specifies the action to be performed */
#define OBEX_HI_ACTIONID          0x94
/* the destination object name */
#define OBEX_HI_DESNAME           0x15
/* 4 byte bit mask for setting permissions */
#define OBEX_HI_PERMISSION        0xd6
/* 1 byte value to setup single response mode */
#define OBEX_HI_SRMODE            0x97
/* 1 byte value for setting parameters used during SRM */
#define OBEX_HI_SRMODE_PARAM      0x98

/* [0x19, 0x2f] => reserved for future use */
/* [0x30, 0x3f] => user defined */

/*
  typedef struct {
  uint8_t hi;
  uint16_t body_len_netord;
  uint8_t chunk[0];
  } __attribute__((packed)) obex_body_hdr;
*/

#define OBEX_REQC_CONNECT        0x80
#define OBEX_REQC_DISCONNECT     0x81
#define OBEX_REQC_PUT            0x02
#define OBEX_REQC_GET            0x03
/* #define OBEX_REQC_RESERVED 0x04 */
#define OBEX_REQC_SETPATH        0x85
#define OBEX_REQC_ACTION         0x06
#define OBEX_REQC_SESSION        0x87
#define OBEX_REQC_ABORT          0xff

/* [0x08, 0x0f] reserved */
/* [0x10, 0x1f] user defined */

#define OBEX_RESC_CONT                   0x10
#define OBEX_RESC_OK                     0x20
#define OBEX_RESC_CREATE                 0x21
#define OBEX_RESC_ACCEPT                 0x22
#define OBEX_RESC_NON_AUTHINFO           0x23  
#define OBEX_RESC_NO_CONTENT             0x24
#define OBEX_RESC_RESET_CONTENT          0x25
#define OBEX_RESC_PARTIAL_CONTENT        0x26
#define OBEX_RESC_MUL_CHOICES            0x30
#define OBEX_RESC_MOVED_PERMAN           0x31
#define OBEX_RESC_MOVED_TEMP             0x32
#define OBEX_RESC_SEEOTHER               0x33
#define OBEX_RESC_NOT_MODIFIED           0x34
#define OBEX_RESC_USE_PROXY              0x35
#define OBEX_RESC_BAD_REQ                0x40
#define OBEX_RESC_UNAUTH                 0x41
#define OBEX_RESC_PAYMENT_REQ            0x42
#define OBEX_RESC_FORBIDDEN              0x43
#define OBEX_RESC_NOT_FOUND              0x44
#define OBEX_RESC_METHOD_DISALLOW        0x45
#define OBEX_RESC_NOT_ACCEPTABLE         0x46
#define OBEX_RESC_PROXY_AUTHREQ          0x47
#define OBEX_RESC_REQTIMEOUT             0x48
#define OBEX_RESC_CONFLICT               0x49
#define OBEX_RESC_GONE                   0x4a
#define OBEX_RESC_LENGTH_REQ             0x4b
#define OBEX_RESC_PRECOND_FAILED         0x4c
#define OBEX_RESC_REQ_ENTITY_TOOLARGE    0x4d
#define OBEX_RESC_REQ_URL_TOOLARGE       0x4e
#define OBEX_RESC_UNKNOWN_MEDIA_TYPE     0x4f
#define OBEX_RESC_INTERNAL_SERVER_ERR    0x50
#define OBEX_RESC_NOTIMPL                0x51
#define OBEX_RESC_BAD_GATEWAY            0x52
#define OBEX_RESC_SERVICE_UNAVAILABLE    0x53
#define OBEX_RESC_GATEWAY_TIMEOUT        0x54
#define OBEX_RESC_HTTPVER_UNSUPP         0x55
#define OBEX_RESC_DB_FULL                0x60
#define OBEX_RESC_DB_LOCKED              0x61

/* [0x00, 0x0f] => reserved */

/**
 * obex_header - Structure used to represents a header in OBEX,
 *               some information can be attached at the tail.
 * @hi:          hedaer identifier
 * @hv:          header value,depends on @hi
 */
struct obex_header {
        uint8_t hi;
        uint8_t hv[0];
} __attribute__((packed));

struct obex_packet {
        uint8_t packet_code;
        uint16_t packet_len_netord;
        uint8_t packet_data[0];
} __attribute__((packed));

typedef struct obex_packet obex_request_t;
typedef struct obex_packet obex_response_t;


/* maximum packet size in bytes */
#define MAX_OBEX_PACKET_SIZE (64U * 1024U - 1U)

/* minimum packet size in bytes */
#define MIN_OBEX_PACKET_SIZE 255U

/* current version number */
#define OBEX_CURR_VERSION_NUM 0x10

/* minimal connect packet size */
#define OBEX_MINI_CONNECTREQ_SIZE 7

#define OBEX_CONNECT_VERN_OFFSET 3
#define OBEX_CONNECT_FLAGS_OFFSET 4
#define OBEX_CONNECT_MPSIZE_OFFSET 5
#define OBEX_CONNECT_OPT_OFFSET 7

#endif /* _OBEX_PACKET_H_ */
