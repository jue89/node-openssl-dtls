#include "helper.h"
#include <openssl/err.h>

void throwGlobalSSLError() {
	char errStr[256];
	ERR_error_string_n(ERR_get_error(), errStr, sizeof(errStr));
	Nan::ThrowError(errStr);
}

BIO * bufferToBio(BIO * bio, v8::Local<v8::Object> & buffer) {
	if (bio == NULL) bio = BIO_new(BIO_s_mem());
	BIO_write(bio, (void*) node::Buffer::Data(buffer), node::Buffer::Length(buffer));
	return bio;
}
