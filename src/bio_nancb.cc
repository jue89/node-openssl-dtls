#include "bio_nancb.h"
#include <nan.h>

static int bio_create (BIO *b) {
	BIO_set_init(b, 1);
	BIO_set_data(b, NULL);
	return 1;
}

static int bio_destroy (BIO *b) {
	if (!b) return 0;
	BIO_set_init(b, 0);
	BIO_set_data(b, NULL);
	return 1;
}

static int bio_write (BIO *b, const char * buf, int len) {
	if (!b) return -1;
	if (!BIO_get_data(b)) return -1;

	Nan::Callback * cb = (Nan::Callback *) BIO_get_data(b);
	char * data = (char*) malloc(len);
	memcpy(data, buf, len);
	Nan::MaybeLocal<v8::Object> dataLocalMaybe = Nan::NewBuffer(data, len);
	v8::Local<v8::Value> dataLocal = dataLocalMaybe.ToLocalChecked();
	Nan::Call(cb->GetFunction(), Nan::GetCurrentContext()->Global(), 1, &dataLocal);

	return len;
}

static long bio_ctrl (BIO *b, int cmd, long num, void *ptr) {
	switch (cmd) {
	case BIO_CTRL_FLUSH:
		return 1;
	case BIO_NANCB_SET_CALLBACK:
		BIO_set_data(b, ptr);
		return 1;
	}

	return 0;
}

static BIO_METHOD *bio_nancb = NULL;

int BIO_nancb_init() {
	bio_nancb = BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_get_new_index(), "nancb");

	if (bio_nancb == NULL ||
	    !BIO_meth_set_write(bio_nancb, bio_write) ||
	    !BIO_meth_set_ctrl(bio_nancb, bio_ctrl) ||
	    !BIO_meth_set_create(bio_nancb, bio_create) ||
	    !BIO_meth_set_destroy(bio_nancb, bio_destroy)) {
		return -1;
	}

	return 0;
}

BIO_METHOD * BIO_nancb() {
	return bio_nancb;
}
