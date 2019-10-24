#ifndef SESSION_H
#define SESSION_H

#include <nan.h>
#include <openssl/ssl.h>

#define ARG_SESSION(ARGNO, ARGVAR) \
	Nan::MaybeLocal<v8::Object> ARGVAR##_MaybeLocal = Nan::To<v8::Object>(info[ARGNO]); \
	if (ARGVAR##_MaybeLocal.IsEmpty()) { \
		Nan::ThrowError("Argument " #ARGNO " must be a session"); \
		return; \
	} \
	Session * ARGVAR = Nan::ObjectWrap::Unwrap<Session>(ARGVAR##_MaybeLocal.ToLocalChecked());

class Session : public Nan::ObjectWrap {
public:
	SSL * handle;
	char * cookie;
	size_t cookieLen;
	static NAN_MODULE_INIT(Init);

private:
	Nan::Callback * cbSend;
	Nan::Callback * cbMessage;
	Nan::Callback * cbConnected;
	Nan::Callback * cbError;
	Nan::Callback * cbShutdown;
	explicit Session(SSL_CTX * ctx, int64_t mtu, const char * cookie, size_t cookieLen, v8::Local<v8::Function> & cbSend, v8::Local<v8::Function> & cbMessage, v8::Local<v8::Function> & cbConnected, v8::Local<v8::Function> & cbError, v8::Local<v8::Function> & cbShutdown);
	~Session();
	void emitError();
	static NAN_METHOD(New);
	static NAN_METHOD(getPeerCert);
	static NAN_METHOD(handler);
	static NAN_METHOD(close);
	static NAN_METHOD(send);
	static Nan::Persistent<v8::Function> constructor;
};

extern int exSessionIdx;

#endif
