#define _POSIX_C_SOURCE 200112L

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "obex_packet_def.h"
#include "obex_helpers.h"

#define BLUETOOTH_MAX_CHANNELS 30

/* 2^15 */
//#define FILE_CHUNK_SIZE 32768
#define FILE_CHUNK_SIZE 1024

#define OBEX_RESERVED_SIZE 128
/* 33280 B */
#define DEFAULT_OBEX_PACKET_SIZE (FILE_CHUNK_SIZE + OBEX_RESERVED_SIZE)

static void print_help_msg(void)
{
        printf("usage: @program <bt-address> <rfcomm channel for push> <filename>\n");
        printf("# command \"spdtool browser <bt-address>\" can be used to scan rfcomm\n"
               "  channels.\n");
        printf("TODO: support SDP.\n");
}

static int start_object_transferring(int obex_sock, int fd, const char *file_name,
                                     size_t file_size, size_t fbuffer_size,
                                     enum MIME_TYPE mime)
{
        int ret = 0;
        void *fchunk = malloc(sizeof(uint8_t) * fbuffer_size);
        if (!fchunk) {
                perror("error: allocate file buffer failed.\n");
                return -1;
        }
        memset(fchunk, 0, fbuffer_size);
        ret = read(fd, fchunk, fbuffer_size);
        if (ret < 0) {
                perror("error: read file failed.\n");
                goto exit_err_free;
        } else if (!ret) {
                perror("error: file EOF at beginning.\n");
                ret = -1;
                goto exit_err_free;
        }

        int all = (ret == file_size);
        printf("sending initial PUT.\n");
        ret = obex_send_initial_put(obex_sock, file_name, file_size,
                                    fchunk, ret, mime, all);
        if (ret < 0) {
                perror("error: send initial PUT message failed.\n");
                ret = -1;
                goto exit_err_free;
        }

        /* the first packet contains all thing */
        if (all) {
                ret = 0;
                goto exit_err_free;
        }

        printf("sending rest object data.\n");
        do {
                ret = read(fd, fchunk, fbuffer_size);
                if (ret < 0) {
                        perror("error: read file failed.\n");
                        goto exit_err_free;
                }
                if (!ret) /* EOF */
                        break;

                ret = obex_send_middle_put(obex_sock, fchunk, ret);
                if (ret < 0) {
                        perror("error: send object data failed.\n");
                        goto exit_err_free;
                }
        } while (1);

        printf("sending EOB.\n");
        ret = obex_send_final_put(obex_sock);

exit_err_free:
        free(fchunk);
        return ret;
}

static int try_rfcomm_connect(const char *bt_address, uint8_t channel)
{
        int ret_socket = -1;
        struct sockaddr_rc rc_addr = {
                .rc_family = AF_BLUETOOTH,
                .rc_channel = channel,
        };
        str2ba(bt_address, &rc_addr.rc_bdaddr);
        int rfcomm_sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
        if (rfcomm_sock < 0) {
                perror("error: open bluetooth socket failed.\n");
                fprintf(stderr, " - %s\n", strerror(errno));
                return -1;
        }
        errno = 0;
        if (connect(rfcomm_sock, (struct sockaddr *)&rc_addr, sizeof(rc_addr)) < 0) {
                perror("error: try connect to channel failed.\n");
                fprintf(stderr, " - channel: %u\n", channel);
                fprintf(stderr, " - %s\n", strerror(errno));
                goto exit_err_close;
        }
        printf("succeed connec to %s at channel %hu\n", bt_address, rc_addr.rc_channel);
        return rfcomm_sock;

exit_err_close:
        (void)shutdown(rfcomm_sock ,SHUT_RDWR);
        return -1;
}

int main(int argc, char *argv[])
{
        if (argc != 4) {
                print_help_msg();
                return 0;
        }

        const char *fpath = argv[3];
        const char *push_channel = argv[2];
        const char *bt_addr = argv[1];
        int fd = -1, rfcomm_sock = -1;
        int ret = 0;

        const char *last_slash = strrchr(fpath, '/');
        const char *file_name = !last_slash ? fpath : last_slash + 1;
        if (*file_name == '\0') {
                perror("error: do not support transfer directory.\n");
                return -1;
        }

        enum MIME_TYPE mime;
        const char *psuffix = strrchr(file_name, '.');
        if (psuffix) {
                if (strncmp(psuffix, ".txt", 5) == 0)
                        mime = MIMET_TXT;
                else if (strncmp(psuffix, ".jpg", 5) == 0)
                        mime = MIMET_JPG;
                else if (strncmp(psuffix, ".jpeg", 6) == 0)
                        mime = MIMET_JPEG;
                else if (strncmp(psuffix, ".png", 5) == 0)
                        mime = MIMET_PNG;
                else {
                        fprintf(stderr,
                                "error: unsupported mime type with suffix %s .\n",
                                psuffix);
                        return -1;
                }
        } else {
                fprintf(stderr, "error: unknown mime type.\n");
                return -1;
        }

        uint8_t channel = atoi(push_channel);
        if (!channel || channel > BLUETOOTH_MAX_CHANNELS) {
                fprintf(stderr, "error: the channel %hu must in range [1, 30].\n",
                        channel);
                return -1;
        }
        
        rfcomm_sock = try_rfcomm_connect(bt_addr, channel);
        if (rfcomm_sock < 0) {
                perror("error: all retry failed.\n");
                return -1;
        }

        /* file size */
        size_t fsize = 0;
        struct stat finfo = {0};
        if (lstat(fpath, &finfo) < 0) {
                perror("error: retrieve file info failed.\n");
                ret = -1;
                goto exit_close;
        } else {
                if (!S_ISREG(finfo.st_mode)) {
                        perror("error: only support regular file.\n");
                        ret = -1;
                        goto exit_close;
                }
                fsize = finfo.st_size;
                if (!fsize) {
                        perror("error: zero size file.\n");
                        ret = -1;
                        goto exit_close;
                }
        }
        printf("target file's size is %lu bytes.\n", fsize);

        /* open file */
        errno = 0;
        fd = open(fpath, O_RDONLY);
        if (fd < 0) {
                fprintf(stderr, "error: open file %s failed.\n",
                        fpath);
                fprintf(stderr, " - %s\n", strerror(errno));
                ret = -1;
                goto exit_close;
        }

        printf("send OBEX CONNECT to peer.\n");
        uint16_t packet_size = DEFAULT_OBEX_PACKET_SIZE;
        ret = obex_try_connect(rfcomm_sock, 0, &packet_size);
        if (ret < 0) {
                perror("error: send CONNECT packet failed.\n");
                goto exit_close;
        } else if (!packet_size) {
                ret = -1;
                perror("error: peer wants zero packet size.\n");
                goto exit_close;
        }
        printf("peer expected packet size is %hu\n", packet_size);
        if (packet_size < OBEX_RESERVED_SIZE) {
                perror("error: the expected packet size is too small.\n");
                goto exit_close;
        }

        /* adjust file size */
        size_t file_buffer_size = FILE_CHUNK_SIZE;
        while (packet_size < file_buffer_size + OBEX_RESERVED_SIZE){
                file_buffer_size /= 2;
        }
        printf("packet size is %u, file chunk size is %u\n",
               file_buffer_size + OBEX_RESERVED_SIZE,
               file_buffer_size);
        
        ret = start_object_transferring(rfcomm_sock, fd, file_name, fsize,
                                        file_buffer_size, mime);
        if (ret < 0) {
                perror("error: send object failed.\n");
        }

        obex_send_disconnect(rfcomm_sock);

        printf("exit...\n");

exit_close:
        (void)close(rfcomm_sock);
        (void)close(fd);
        return ret;
}
