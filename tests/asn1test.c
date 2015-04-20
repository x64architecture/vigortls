#include <openssl/x509.h>
#include <openssl/asn1_mac.h>

typedef struct X {
    STACK_OF(X509_EXTENSION) * ext;
} X;

/* This isn't meant to run particularly, it's just to test type checking */
int main(int argc, char **argv)
{
    X *x = NULL;
    unsigned char **pp = NULL;

    M_ASN1_I2D_vars(x);
    M_ASN1_I2D_seq_total();
    M_ASN1_I2D_finish();
}
