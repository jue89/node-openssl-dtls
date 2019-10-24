#include "bio_nancb.h"
#include <nan.h>

static int bio_create (BIO *b) {
	b->init = 1;
	b->ptr = NULL;
	b->flags = 0;
	b->num = 0;
	return 1;
}

static int bio_destroy (BIO *b) {
	if (!b) return 0;
	b->ptr = NULL;
	b->init = 0;
	b->flags = 0;
	return 1;
}

static int bio_write (BIO *b, const char * buf, int len) {
	if (!b) return -1;
	if (!b->ptr) return -1;

	Nan::Callback * cb = (Nan::Callback *) b->ptr;
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
		b->ptr = ptr;
		return 1;
	}

	return 0;
}

static BIO_METHOD bio_nancb {
	BIO_TYPE_SOURCE_SINK,
	"nancb",
	bio_write,
	NULL,
	NULL,
	NULL,
	bio_ctrl,
	bio_create,
	bio_destroy,
	NULL
};

BIO_METHOD * BIO_nancb() {
	return &bio_nancb;
}
