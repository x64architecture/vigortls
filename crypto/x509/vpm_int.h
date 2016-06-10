
/* Internal only structure to hold additional X509_VERIFY_PARAM data */

struct X509_VERIFY_PARAM_ID_st
{
    uint8_t *host;          /* If not NULL hostname to match */
    unsigned int hostflags; /* Flags to control matching features */
    uint8_t *email;         /* If not NULL email address to match */
    size_t emaillen;
    uint8_t *ip;            /* If not NULL IP address to match */
    size_t iplen;           /* Length of IP address */
};
