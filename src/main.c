#define _POSIX_C_SOURCE 200112L

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "obex_agent_data_def.h"
#include "obex_agent.h"

#include "mime_type.h"

/* 2^15 */
//#define FILE_CHUNK_SIZE 32768
#define FILE_CHUNK_SIZE 4096

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

static size_t adjust_fbuffer_size(size_t expect, size_t curr, size_t reserve)
{
        if (expect < reserve)
                return 0;
        while (expect < curr + reserve) {
                fprintf(stderr, "expect is %zu, curr is %zu, reserve is %zu, curr + reserve is %zu\n",
                        expect, curr, reserve, curr + reserve);
                curr /= 2;
        }
        return curr;
}

static int start_object_transferring(int fd, const char *fname_nosuffix,
                                     size_t file_size, const char *type,
                                     const char *peer_addr, uint8_t channel)
{
        struct obex_connect_agent *cagent = NULL;
        const struct obex_connect_agent_operations *caops = NULL;
        struct obex_put_agent *pagent = NULL;
        const struct obex_put_agent_operations *paops = NULL;
        union obex_agent_data *pad = NULL;
        const struct obex_pad_operations *padops = NULL;

        int ret = 0;
        size_t fbsize = DEFAULT_OBEX_PACKET_SIZE;
        size_t chunk_size = FILE_CHUNK_SIZE;
        cagent = ctor_obex_ca(peer_addr, channel, 0, fbsize);
        if (!cagent) {
                fprintf(stderr, "error: Failed to start CONNECT Agent\n");
                return -1;

        }
        caops = cagent->ca_ops;
        ret = caops->connect(cagent, 1);
        if (ret < 0) {
                fprintf(stderr, "error: Failed to establish connection\n");
                fprintf(stderr, "error: - %s\n", strerror(-1 * ret));
                goto exit_dtor_cagent;
        }
        printf("Succeed to establish RFCOMM connection at channel %hu\n", channel);
        printf("Peer expected packet size is %zu\n", cagent->packet_size);
        fbsize = adjust_fbuffer_size(cagent->packet_size, chunk_size, OBEX_RESERVED_SIZE);
        if (!fbsize) {
                fprintf(stderr, "error: Bad file buffer size 0\n");
                ret = -1;
                goto exit_dtor_cagent;
        }
        printf("We select chunk size %zu\n", fbsize);

        pagent = ctor_obex_pa();
        if (!pagent) {
                fprintf(stderr, "error: Failed to start PUT Agent\n");
                ret = -1;
                goto exit_dtor_cagent;
        }
        paops = pagent->pa_ops;
        padops = pagent->pad_ops;
        pad = &pagent->pad;
        
        paops->register_fd(pagent, fd);
        paops->register_rfcommsock(pagent, cagent->rfcomm_socket);
        
        padops->mod_name(pad, fname_nosuffix);
        padops->mod_type(pad, type);
        padops->mod_length(pad, file_size);
        padops->mod_chunk_size(pad, fbsize);

        ret = paops->push_object(pagent);
        if (ret < 0) {
                fprintf(stderr, "error: Faild to send file\n");
                fprintf(stderr, "- %s\n", strerror(-1 * ret));
                fprintf(stderr, "Status: %#x\n", pagent->status_code);
                ret = -1;
        }

        obex_pa_put(pagent);
        
exit_dtor_cagent:
        obex_ca_put(cagent);
        return ret;
}

static inline ssize_t get_file_size(const char *filepath)
{
        struct stat tmp = {0};
        if (lstat(filepath, &tmp) < 0)
                return -1;

        return S_ISREG(tmp.st_mode) ? tmp.st_size : -1;
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
                perror("error: Do not support transfer directory\n");
                return -1;
        }

        enum MIME_TYPE mime;
        const char *psuffix = strrchr(file_name, '.');
        mime = suffix2mime(psuffix);
        const char *mime_type_str = get_mime_type(mime);
        uint8_t channel = atoi(push_channel);

        /* file size */
        size_t fsize = get_file_size(fpath);
        if (fsize < 0) {
                perror("error: failed to get file size or is not regular file.\n");
                ret = -1;
                goto exit_close;
        }
        printf("Target file's size is %lu bytes\n", fsize);

        /* open file */
        errno = 0;
        fd = open(fpath, O_RDONLY);
        if (fd < 0) {
                fprintf(stderr, "error: Open file %s failed\n",
                        fpath);
                fprintf(stderr, " - %s\n", strerror(errno));
                ret = -1;
                goto exit_close;
        }
        ret = start_object_transferring(fd, file_name, fsize,
                                        mime_type_str, bt_addr, channel);
        if (ret < 0) {
                perror("error: send object failed.\n");
        }

        printf("exit...\n");
exit_close:
        (void)close(rfcomm_sock);
        (void)close(fd);
        return ret;
}
