#include <openssl/ssl.h>
#include "context.h"
#include "session.h"
#include "bio_nancb.h"

NAN_MODULE_INIT(Init) {
	SSL_load_error_strings();
	SSL_library_init();
	BIO_nancb_init();
	Context::Init(target);
	Session::Init(target);
}

NODE_MODULE(dlts, Init)
