#ifndef _MIME_TYPE_H_
#define _MIME_TYPE_H_

#include <assert.h>
#include <stddef.h>

enum MIME_TYPE {
        MIMET_TXT,
        MIMET_JPG,
        MIMET_JPEG = MIMET_JPG,
        MIMET_PNG,
        MIMET_SUPPORTED_MAX,
};

extern const char *mime_type_table[MIMET_SUPPORTED_MAX];

static inline const char *get_mime_type(enum MIME_TYPE t)
{
        assert(t < MIMET_SUPPORTED_MAX);
        return mime_type_table[t];
}

#endif /* mime_type.h */
