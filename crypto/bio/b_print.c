/* Kurt Cancemi places this file in the public domain. */

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

#ifdef OPENSSL_SYS_WIN32
int vasprintf(char **buf, const char *format, va_list args)
{
    int wanted = vsnprintf(*buf = NULL, 0, format, args);
    if((wanted < 0) || ((*buf = OPENSSL_malloc(wanted + 1)) == NULL))
        return -1;

    return vsprintf(*buf, format, args);
}
#endif
