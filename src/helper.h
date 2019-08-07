#ifndef HELPER_H
#define HELPER_H

#include <nan.h>
#include <openssl/bio.h>

#define ARG_INT(ARGNO, ARGVAR) \
	Nan::MaybeLocal<v8::Integer> ARGVAR##_MaybeLocal = Nan::To<v8::Integer>(info[ARGNO]); \
	if (ARGVAR##_MaybeLocal.IsEmpty()) { \
		Nan::ThrowError("Argument " #ARGNO " must be a number"); \
		return; \
	} \
	v8::Local<v8::Integer> ARGVAR##_Local = ARGVAR##_MaybeLocal.ToLocalChecked(); \
	int64_t ARGVAR = ARGVAR##_Local->Value();

#define ARG_STRING(ARGNO, ARGVAR) \
	Nan::MaybeLocal<v8::String> ARGVAR##_MaybeLocal = Nan::To<v8::String>(info[ARGNO]); \
	if (ARGVAR##_MaybeLocal.IsEmpty()) { \
		Nan::ThrowError("Argument " #ARGNO " must be a string"); \
		return; \
	} \
	v8::Local<v8::String> ARGVAR##_Local = ARGVAR##_MaybeLocal.ToLocalChecked(); \
	Nan::Utf8String ARGVAR(ARGVAR##_Local);

#define ARG_BUFFER(ARGNO, ARGVAR) \
	Nan::MaybeLocal<v8::Object> ARGVAR##_MaybeLocal = Nan::To<v8::Object>(info[ARGNO]); \
	if (ARGVAR##_MaybeLocal.IsEmpty()) { \
		Nan::ThrowError("Argument " #ARGNO " must be a buffer"); \
		return; \
	} \
	v8::Local<v8::Object> ARGVAR = ARGVAR##_MaybeLocal.ToLocalChecked();

#define OPTARG_BUFFER(ARGNO, ARGVAR) \
	Nan::MaybeLocal<v8::Object> ARGVAR##_MaybeLocal = Nan::To<v8::Object>(info[ARGNO]); \
	if (ARGVAR##_MaybeLocal.IsEmpty()) { \
		Nan::ThrowError("Argument " #ARGNO " must be a buffer"); \
		return; \
	} \
	v8::Local<v8::Object> ARGVAR = ARGVAR##_MaybeLocal.ToLocalChecked();

#define ARG_FUN(ARGNO, ARGVAR) \
	Nan::MaybeLocal<v8::Function> ARGVAR##_MaybeLocal = Nan::To<v8::Function>(info[ARGNO]); \
	if (ARGVAR##_MaybeLocal.IsEmpty()) { \
		Nan::ThrowError("Argument " #ARGNO " must be a function"); \
		return; \
	} \
	v8::Local<v8::Function> ARGVAR = ARGVAR##_MaybeLocal.ToLocalChecked();

void throwGlobalSSLError();
BIO * bufferToBio(BIO * bio, v8::Local<v8::Object> & buffer);

#endif
