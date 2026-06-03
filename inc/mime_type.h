/**
 * This header contains supported mime type enumerators.
 */
#ifndef _MIME_TYPE_H_
#define _MIME_TYPE_H_

#include <assert.h>
#include <stddef.h>

/**
 * MIME_TYPE - enumeration type for mime types
 */
enum MIME_TYPE {
        MIMET_TXT,
        MIMET_JPG,
        MIMET_JPEG = MIMET_JPG,
        MIMET_PNG,
        MIMET_PDF,
        MIMET_ZIP,
        MIMET_MSWORD,
        MIMET_MSEXCEL,
        MIMET_MSEXE,
        MIMET_BIN,
        MIMET_SUPPORTED_MAX,
};
extern const char *mime_type_table[MIMET_SUPPORTED_MAX];

static inline const char *get_mime_type(enum MIME_TYPE t)
{
        assert(t < MIMET_SUPPORTED_MAX);
        return mime_type_table[t];
}

extern enum MIME_TYPE suffix2mime(const char *);

#endif /* mime_type.h */
