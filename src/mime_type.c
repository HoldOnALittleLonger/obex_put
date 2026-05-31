#include <string.h>

#include "mime_type.h"

const char *mime_type_table[MIMET_SUPPORTED_MAX] = {
        "text/plain",
        "image/jpeg",
        "image/png",
};

enum MIME_TYPE suffix2mime(const char *suffix)
{
        enum MIME_TYPE mime = MIMET_SUPPORTED_MAX;
        if (suffix)
                if (strncmp(suffix, ".txt", 5) == 0)
                        mime = MIMET_TXT;
                else if (strncmp(suffix, ".jpg", 5) == 0)
                        mime = MIMET_JPG;
                else if (strncmp(suffix, ".jpeg", 6) == 0)
                        mime = MIMET_JPEG;
                else if (strncmp(suffix, ".png", 5) == 0)
                        mime = MIMET_PNG;

        return mime;
}
