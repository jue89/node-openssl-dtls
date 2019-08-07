#ifndef CONTEXT_H
#define CONTEXT_H

#include <nan.h>
#include <openssl/ssl.h>

#define ARG_CONTEXT(ARGNO, ARGVAR) \
	Nan::MaybeLocal<v8::Object> ARGVAR##_MaybeLocal = Nan::To<v8::Object>(info[ARGNO]); \
	if (ARGVAR##_MaybeLocal.IsEmpty()) { \
		Nan::ThrowError("Argument " #ARGNO " must be a context"); \
		return; \
	} \
	Context * ARGVAR = Nan::ObjectWrap::Unwrap<Context>(ARGVAR##_MaybeLocal.ToLocalChecked());

class Context : public Nan::ObjectWrap {
public:
	SSL_CTX * handle;
	static NAN_MODULE_INIT(Init);

private:
	explicit Context(const SSL_METHOD * meth);
	~Context();
	static Nan::Persistent<v8::Function> constructor;
	static NAN_METHOD(New);
	static NAN_METHOD(setCiphers);
	static NAN_METHOD(setCertAndKey);
	static NAN_METHOD(setCA);
	static NAN_METHOD(setVerifyLevel);
};

#endif
