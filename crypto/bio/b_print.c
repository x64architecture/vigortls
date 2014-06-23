/* Public domain. */

#include <openssl/bio.h>

int BIO_printf(BIO *bio, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = BIO_vprintf(bio, format, args);
    va_end(args);
    return (ret);
}

int BIO_vprintf(BIO *bio, const char *format, va_list args)
{
    int ret;
    char *buf = NULL;

    ret = vasprintf(&buf, format, args);
    if (buf == NULL) {
        ret = -1;
        goto fail;
    }
    BIO_write(bio, buf, ret);
    OPENSSL_free(buf);
fail:
    return (ret);
}


int BIO_snprintf(char *buf, size_t n, const char *format, ...)
{
    va_list args;
    int ret;

    va_start(args, format);
    ret = vsnprintf(buf, n, format, args);
    va_end(args);

    if (ret >= n || ret == -1)
        return (-1);
    return (ret);
}

int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
{
	int ret;

    ret = vsnprintf(buf, n, format, args);

    if (ret >= n || ret == -1)
        return (-1);
    return (ret);
}
