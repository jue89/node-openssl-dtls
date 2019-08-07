#include "context.h"
#include "helper.h"
#include <openssl/err.h>

NAN_MODULE_INIT(Context::Init) {
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
	tpl->SetClassName(Nan::New("Context").ToLocalChecked());
	tpl->InstanceTemplate()->SetInternalFieldCount(1);

	Nan::SetPrototypeMethod(tpl, "setCiphers", setCiphers);
	Nan::SetPrototypeMethod(tpl, "setCertAndKey", setCertAndKey);
	Nan::SetPrototypeMethod(tpl, "setCA", setCA);
	Nan::SetPrototypeMethod(tpl, "setVerifyLevel", setVerifyLevel);

	constructor.Reset(Nan::GetFunction(tpl).ToLocalChecked());
	Nan::Set(target, Nan::New("Context").ToLocalChecked(), Nan::GetFunction(tpl).ToLocalChecked());
}

NAN_METHOD(Context::New) {
	Context * ctx = new Context(DTLSv1_2_server_method());
	ctx->Wrap(info.This());
	info.GetReturnValue().Set(info.This());
}

Context::Context(const SSL_METHOD * meth) {
	int rc;

	// Create a new SSL_CTX
	this->handle = SSL_CTX_new(meth);
	if (this->handle == NULL) goto error;

	// Create a new key pair for ECDHE
	rc = SSL_CTX_set_tmp_ecdh(this->handle, EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
	if (!rc) goto error;

	// TODO: Set cookie callbacks

	return;

error:
	throwGlobalSSLError();
}

Context::~Context() {
	// Remove handle
	if (this->handle) SSL_CTX_free(this->handle);
}

NAN_METHOD(Context::setCiphers) {
	ARG_STRING(0, ciphers);
	Context * ctx = Nan::ObjectWrap::Unwrap<Context>(info.Holder());

	int rc = SSL_CTX_set_cipher_list(ctx->handle, *ciphers);
	if (!rc) throwGlobalSSLError();

	// SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	// SSL_CTX_set_read_ahead(ctx, 1);
}

static int noPasswordCallback(char *buf, int size, int rwflag, void *u) {
	return 0;
}

NAN_METHOD(Context::setCertAndKey) {
	ARG_BUFFER(0, certBuf)
	ARG_BUFFER(1, keyBuf)
	Context * ctx = Nan::ObjectWrap::Unwrap<Context>(info.Holder());
	unsigned long err;
	int rc = 1;
	BIO * certBio;
	X509 * cert = NULL;
	X509 * ca = NULL;
	BIO * keyBio;
	EVP_PKEY * key = NULL;

	// Clear all errors not made in this function
	ERR_clear_error();

	// Convert cert chain into BIO
	certBio = bufferToBio(NULL, certBuf);

	// First certificate is the server / client certificate
	cert = PEM_read_bio_X509_AUX(certBio, NULL, noPasswordCallback, NULL);
	if (cert == NULL) {
		rc = 0;
		goto final;
	}

	rc = SSL_CTX_use_certificate(ctx->handle, cert);
	if (!rc) goto final;

	// Read following (intermediate) CA certificates
	rc = SSL_CTX_clear_chain_certs(ctx->handle);
	if (!rc) goto final;

	while ((ca = PEM_read_bio_X509(certBio, NULL, noPasswordCallback, NULL)) != NULL) {
		rc = SSL_CTX_add0_chain_cert(ctx->handle, ca);
		if (!rc) goto final;
		// Don't free ca if it has been read successfully!
		// Ref counter is not increased by SSL_CTX_add0_chain_cert.
	}

	// When the loop ends, check out whether its EOF or an actual error
	err = ERR_peek_last_error();
	if (ERR_GET_LIB(err) != ERR_LIB_PEM || ERR_GET_REASON(err) != PEM_R_NO_START_LINE) {
		X509_free(ca);
		rc = 0;
		goto final;
	}

	// Convert key into BIO
	keyBio = bufferToBio(NULL, keyBuf);

	// Set private key
	key = PEM_read_bio_PrivateKey(keyBio, NULL, noPasswordCallback, NULL);
	if (key == NULL) {
		rc = 0;
		goto final;
	}

	rc = SSL_CTX_use_PrivateKey(ctx->handle, key);
	if (!rc) goto final;

	// Check private key
	rc = SSL_CTX_check_private_key(ctx->handle);
	if (!rc) goto final;

final:
	if (cert) X509_free(cert);
	if (key) EVP_PKEY_free(key);
	if (!rc) throwGlobalSSLError();
}

NAN_METHOD(Context::setCA) {
	ARG_BUFFER(0, caBuf)
	Context * ctx = Nan::ObjectWrap::Unwrap<Context>(info.Holder());
	int rc = 1;
	X509_STORE * caStore;
	X509_LOOKUP * lu;
	STACK_OF(X509_INFO) * caInfo;
	BIO * caBio;

	caStore = SSL_CTX_get_cert_store(ctx->handle);
	lu = X509_STORE_add_lookup(caStore, X509_LOOKUP_file());
	if (lu == NULL) {
		rc = 0;
		goto final;
	}

	caBio = bufferToBio(NULL, caBuf);
	caInfo = PEM_X509_INFO_read_bio(caBio, NULL, noPasswordCallback, NULL);
	for (int i = 0; i < sk_X509_INFO_num(caInfo); i++) {
		X509_INFO * part = sk_X509_INFO_value(caInfo, i);
		if (part->x509) {
			X509_STORE_add_cert(lu->store_ctx, part->x509);
			SSL_CTX_add_client_CA(ctx->handle, part->x509);
		}
		if (part->crl) {
			X509_STORE_add_crl(lu->store_ctx, part->crl);
		}
	}
	sk_X509_INFO_pop_free(caInfo, X509_INFO_free);

final:
	if (!rc) throwGlobalSSLError();
}

static int verifyCallback(int ok, X509_STORE_CTX *ctx) {
	return ok;
}

NAN_METHOD(Context::setVerifyLevel) {
	ARG_INT(0, verifyLevel)
	Context * ctx = Nan::ObjectWrap::Unwrap<Context>(info.Holder());
	int verifyMode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

	switch (verifyLevel) {
		case 0: verifyMode = SSL_VERIFY_NONE; break;
		case 1: verifyMode = SSL_VERIFY_PEER; break;
		case 2: verifyMode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT; break;
	}

	SSL_CTX_set_verify(ctx->handle, verifyMode, verifyCallback);
}