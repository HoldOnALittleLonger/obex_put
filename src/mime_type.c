#include <string.h>

#include "mime_type.h"

const char *mime_type_table[MIMET_SUPPORTED_MAX] = {
        [MIMET_TXT] = "text/plain",
        [MIMET_JPG] = "image/jpeg",
        [MIMET_PNG] = "image/png",
        [MIMET_PDF] = "application/pdf",
        [MIMET_ZIP] = "application/zip",
        [MIMET_MSWORD] = "application/msword",
        [MIMET_MSEXCEL] = "application/vnd.ms-excel",
        [MIMET_MSEXE] = "application/x-msdownload",
        [MIMET_BIN] = "application/octet-stream",
};

enum MIME_TYPE suffix2mime(const char *suffix)
{
        /* default to binary file */
        enum MIME_TYPE mime = MIMET_BIN;
        if (suffix)
                if (strncmp(suffix, ".txt", 5) == 0)
                        mime = MIMET_TXT;
                else if (strncmp(suffix, ".jpg", 5) == 0)
                        mime = MIMET_JPG;
                else if (strncmp(suffix, ".jpeg", 6) == 0)
                        mime = MIMET_JPEG;
                else if (strncmp(suffix, ".png", 5) == 0)
                        mime = MIMET_PNG;
                else if (strncmp(suffix, ".pdf", 5) == 0)
                        mime = MIMET_PDF;
                else if (strncmp(suffix, ".zip", 5) == 0)
                        mime = MIMET_ZIP;
                else if (strncmp(suffix, ".doc", 5) == 0)
                        mime = MIMET_MSWORD;
                else if (strncmp(suffix, ".xls", 5) == 0)
                        mime = MIMET_MSEXCEL;
                else if (strncmp(suffix, ".exe", 5) == 0)
                        mime = MIMET_MSEXE;
        
        return mime;
}
