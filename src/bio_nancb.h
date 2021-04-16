#ifndef BIO_NANCB_H
#define BIO_NANCB_H

#include <openssl/bio.h>

#define BIO_NANCB_SET_CALLBACK 104

int BIO_nancb_init();

#define BIO_nancb_set_cb(b,cb) BIO_ctrl(b,BIO_NANCB_SET_CALLBACK,0,(void *)cb)

BIO_METHOD * BIO_nancb();

#endif
