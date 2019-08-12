#include "session.h"
#include "context.h"
#include "helper.h"
#include "bio_nancb.h"
#include <node_buffer.h>
#include <openssl/err.h>

int exSessionIdx;

Nan::Persistent<v8::Function> Session::constructor;

NAN_MODULE_INIT(Session::Init) {
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
	tpl->SetClassName(Nan::New("Session").ToLocalChecked());
	tpl->InstanceTemplate()->SetInternalFieldCount(1);

	Nan::SetPrototypeMethod(tpl, "handler", handler);
	Nan::SetPrototypeMethod(tpl, "close", close);
	Nan::SetPrototypeMethod(tpl, "getPeerCert", getPeerCert);
	Nan::SetPrototypeMethod(tpl, "send", send);

	constructor.Reset(Nan::GetFunction(tpl).ToLocalChecked());
	Nan::Set(target, Nan::New("Session").ToLocalChecked(), Nan::GetFunction(tpl).ToLocalChecked());

	// Register new ex data index for Session instance pointer
	exSessionIdx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
}

NAN_METHOD(Session::New) {
	ARG_CONTEXT(0, ctx);
	ARG_BUFFER(1, cookie);
	ARG_INT(2, mtu);
	ARG_FUN(3, cbSend);
	ARG_FUN(4, cbMessage);
	ARG_FUN(5, cbConnected);
	ARG_FUN(6, cbError);
	ARG_FUN(7, cbShutdown);

	Session * sess = new Session(ctx->handle, mtu, node::Buffer::Data(cookie), node::Buffer::Length(cookie),
	                             cbSend, cbMessage, cbConnected, cbError, cbShutdown);

	sess->Wrap(info.This());
	info.GetReturnValue().Set(info.This());
}

Session::Session(
	SSL_CTX * ctx,
	int64_t mtu,
	const char * cookie,
	size_t cookieLen,
	v8::Local<v8::Function> & cbSend,
	v8::Local<v8::Function> & cbMessage,
	v8::Local<v8::Function> & cbConnected,
	v8::Local<v8::Function> & cbError,
	v8::Local<v8::Function> & cbShutdown
) :
	handle(NULL),
	cookie(NULL),
	cookieLen(0),
	cbSend(NULL),
	cbMessage(NULL),
	cbConnected(NULL),
	cbError(NULL),
	cbShutdown(NULL)
{
	BIO * rbio;
	BIO * wbio;

	// Check cookie length
	if (cookieLen > DTLS1_COOKIE_LENGTH) {
		Nan::ThrowError("Cookie is too long");
		return;
	}

	// Store callbacks
	this->cbSend = new Nan::Callback(cbSend);
	this->cbMessage = new Nan::Callback(cbMessage);
	this->cbConnected = new Nan::Callback(cbConnected);
	this->cbError = new Nan::Callback(cbError);
	this->cbShutdown = new Nan::Callback(cbShutdown);

	// Create a new SSL session
	this->handle = SSL_new(ctx);
	if (this->handle == NULL) goto error;

	// Set BIOs
	rbio = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(rbio, -1);
	wbio = BIO_new(BIO_nancb());
	BIO_nancb_set_cb(wbio, this->cbSend);
	SSL_set_bio(this->handle, rbio, wbio);

	// Store cookie
	this->cookie = (char*) malloc(cookieLen);
	memcpy(this->cookie, cookie, cookieLen);
	this->cookieLen = cookieLen;

	// Make sure to exchange cookies before intialising the handshake
	SSL_set_options(this->handle, SSL_OP_COOKIE_EXCHANGE);

	// Set MTU
	SSL_set_options(this->handle, SSL_OP_NO_QUERY_MTU);
	DTLS_set_link_mtu(this->handle, mtu);

	// Store pointer inside the SSL session
	SSL_set_ex_data(this->handle, exSessionIdx, this);

	// Bring SSL context into accept state (i.e. server)
	SSL_set_accept_state(this->handle);

	return;

error:
	throwGlobalSSLError();
}

Session::~Session() {
	// Remove handle
	if (this->handle) SSL_free(this->handle);
	if (this->cookie) free(this->cookie);
	if (this->cbSend) delete this->cbSend;
	if (this->cbMessage) delete this->cbMessage;
	if (this->cbConnected) delete this->cbConnected;
	if (this->cbError) delete this->cbError;
	if (this->cbShutdown) delete this->cbShutdown;
}

void Session::emitError() {
	char errStr[256];
	ERR_error_string_n(ERR_get_error(), errStr, sizeof(errStr));
	Nan::MaybeLocal<v8::String> errLocalMaybe = Nan::New<v8::String>(errStr);
	v8::Local<v8::Value> errLocal = errLocalMaybe.ToLocalChecked();
	Nan::Call(this->cbError->GetFunction(), Nan::GetCurrentContext()->Global(), 1, &errLocal);
}

NAN_METHOD(Session::handler) {
	Session * sess = Nan::ObjectWrap::Unwrap<Session>(info.Holder());
	int rc;
	uint32_t ret = 0;

	// Write data to BIO if a datagram has been received
	Nan::MaybeLocal<v8::Object> dataBufMaybe = Nan::To<v8::Object>(info[0]);
	if (!dataBufMaybe.IsEmpty()) {
		v8::Local<v8::Object> dataBuf = dataBufMaybe.ToLocalChecked();
		bufferToBio(SSL_get_rbio(sess->handle), dataBuf);
	}

	// Depending on the candidate's state we call the right function
	if (!SSL_is_init_finished(sess->handle)) {
		rc = SSL_do_handshake(sess->handle);
		if (rc == 1) {
			// Connection has been established
			Nan::Call(sess->cbConnected->GetFunction(), Nan::GetCurrentContext()->Global(), 0, NULL);
		} else if (SSL_get_error(sess->handle, rc) == SSL_ERROR_SSL) {
			// An error occured
			sess->emitError();
		} else {
			// Handshake isn't finished, yet
			struct timeval dtlsTimeout = {0, 0};
			DTLSv1_get_timeout(sess->handle, (void*) &dtlsTimeout);
			ret = dtlsTimeout.tv_sec * 1000 + dtlsTimeout.tv_usec / 1000;
		}
	} else {
		char buffer[4096];
		int rc = SSL_read(sess->handle, buffer, sizeof(buffer));
		if (rc <= 0) {
			int err = SSL_get_error(sess->handle, rc);
			if (err == SSL_ERROR_ZERO_RETURN) {
				// Disconnected!
				Nan::Call(sess->cbShutdown->GetFunction(), Nan::GetCurrentContext()->Global(), 0, NULL);
			} else if (err == SSL_ERROR_SSL) {
				// An error occured
				sess->emitError();
			}
		} else if (rc > 0) {
			// Data received from remote side
			char * data = (char*) malloc(rc);
			memcpy(data, buffer, rc);
			Nan::MaybeLocal<v8::Object> dataLocalMaybe = Nan::NewBuffer(data, rc);
			v8::Local<v8::Value> dataLocal = dataLocalMaybe.ToLocalChecked();
			Nan::Call(sess->cbMessage->GetFunction(), Nan::GetCurrentContext()->Global(), 1, &dataLocal);
		}
	}

	// Return amount of millisconds of the retransmit timer
	info.GetReturnValue().Set(Nan::New(ret));
}

NAN_METHOD(Session::close) {
	Session * sess = Nan::ObjectWrap::Unwrap<Session>(info.Holder());

	// Check if session has been shut down or a fatal error orrucred
	// In this case we are not allowed to call SSL_shutdown()
	if (SSL_get_shutdown(sess->handle) & SSL_SENT_SHUTDOWN) return;
	if (SSL_get_state(sess->handle) == SSL_ST_ERR) return;

	SSL_shutdown(sess->handle);
}

NAN_METHOD(Session::getPeerCert) {
	Session * sess = Nan::ObjectWrap::Unwrap<Session>(info.Holder());
	BIO * pem = BIO_new(BIO_s_mem());

	// Get peer's certificate
	X509 * cert = SSL_get_peer_certificate(sess->handle);
	if (cert != NULL) PEM_write_bio_X509(pem, cert);

	// Get peer's remaining certificate chain
	STACK_OF(X509) * chain = SSL_get_peer_cert_chain(sess->handle);
	if (chain != NULL) {
		for (int i = 0; i < sk_X509_num(chain); i++) {
			X509 * cert = sk_X509_value(chain, i);
			PEM_write_bio_X509(pem, cert);
		}
	}

	// Return pem data
	char * data = (char*) malloc(4096);
	int n = BIO_read(pem, data, 4096);
	if (n < 0) n = 0;
	BIO_free(pem);
	Nan::MaybeLocal<v8::Object> certChain = Nan::NewBuffer(data, n);
	info.GetReturnValue().Set(certChain.ToLocalChecked());
}

NAN_METHOD(Session::send) {
	Session * sess = Nan::ObjectWrap::Unwrap<Session>(info.Holder());
	ARG_BUFFER(0, data);
	int rc = SSL_write(sess->handle, node::Buffer::Data(data), node::Buffer::Length(data));
	if (rc <= 0 && SSL_get_error(sess->handle, rc) == SSL_ERROR_SSL) {
		sess->emitError();
	}
}
