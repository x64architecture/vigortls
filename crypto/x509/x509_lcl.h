
/* a sequence of these are used */
struct x509_attributes_st {
    ASN1_OBJECT *object;
    STACK_OF(ASN1_TYPE) *set;
};

int x509_check_cert_time(X509_STORE_CTX *ctx, X509 *x, int quiet);
