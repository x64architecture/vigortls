
/* a sequence of these are used */
struct x509_attributes_st {
    ASN1_OBJECT *object;
    STACK_OF(ASN1_TYPE) *set;
};

int asn1_time_parse(const char *, size_t, struct tm *, int);
int asn1_tm_cmp(struct tm *tm1, struct tm *tm2);
