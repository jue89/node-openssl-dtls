#include <nan.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <map>
#include <string>

//#define DEBUG
#ifdef DEBUG
	#define DEBUGLOG(...) printf(__VA_ARGS__)
#else
	#define DEBUGLOG(...)
#endif

#define COOKIE_SECRET_LENGTH 16
static unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int peerIdx;
struct sockaddr dummy;

// Convert buffer arguments to BIO
static BIO * arg2bio(BIO * bio, Nan::NAN_METHOD_ARGS_TYPE args, int i) {
	v8::Local<v8::Object> buffer;

	if (args[i]->IsUndefined()) return bio;
	if (bio == NULL) bio = BIO_new(BIO_s_mem());

	buffer = args[i]->ToObject();
	BIO_write(bio, (void*) node::Buffer::Data(buffer), node::Buffer::Length(buffer));

	return bio;
}

// This callback is used to avoid the default passphrase callback in OpenSSL
// which will typically prompt for the passphrase.
static int noPasswordCallback(char *buf, int size, int rwflag, void *u) {
	return 0;
}

// Add given BIO containing cert chain to ctx
static int readCertChain(SSL_CTX * ctx, BIO * chain) {
	int rc = 1;
	unsigned long err;
	X509 *x = NULL;
	X509 *ca = NULL;

	// Clear all errors not made in this function
	ERR_clear_error();

	// First certificate is the server / client certificate
	x = PEM_read_bio_X509_AUX(chain, NULL, noPasswordCallback, NULL);
	if (x == NULL) {
		rc = 0;
		goto final;
	}

	rc = SSL_CTX_use_certificate(ctx, x);
	if (!rc) goto final;

	// Read following (intermediate) CA certificates
	rc = SSL_CTX_clear_chain_certs(ctx);
	if (!rc) goto final;

	while ((ca = PEM_read_bio_X509(chain, NULL, noPasswordCallback, NULL)) != NULL) {
		rc = SSL_CTX_add0_chain_cert(ctx, ca);
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

final:
	X509_free(x);
	return rc;
}

static int readPrivateKey(SSL_CTX * ctx, BIO * pkey) {
	int rc = 1;
	EVP_PKEY *x;

	x = PEM_read_bio_PrivateKey(pkey, NULL, noPasswordCallback, NULL);
	if (x == NULL) {
		rc = 0;
		goto final;
	}

	rc = SSL_CTX_use_PrivateKey(ctx, x);
	if (!rc) goto final;

final:
	EVP_PKEY_free(x);
	return rc;
}

static int sslFromCtx(SSL_CTX * ctx, SSL ** ssl) {
	int rc = 1;
	BIO * rbio;
	BIO * wbio;

	*ssl = SSL_new(ctx);
	if (*ssl == NULL) {
		rc = 0;
		goto final;
	}

	// Set up BIO stuff
	rbio = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(rbio, -1);
	wbio = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(wbio, -1);
	SSL_set_bio(*ssl, rbio, wbio);

	// Make sure to exchange cookies before intialising the handshake
	SSL_set_options(*ssl, SSL_OP_COOKIE_EXCHANGE);

	// First mark this context to be listening
	// So we can wait for a valid cookie and then create a new context
	(*ssl)->d1->listen = 1;

	// Setup store for peer identifier
	SSL_set_ex_data(*ssl, peerIdx, new std::string());

	// Bring SSL context into accept state (i.e. server)
	SSL_set_accept_state(*ssl);

	// Set MTU --> TODO Set proper MTU!
	SSL_set_options(*ssl, SSL_OP_NO_QUERY_MTU);
	DTLS_set_link_mtu(*ssl, 1280);

final:
	return rc;
}

static void throwGlobalSSLError() {
	char errStr[256];
	ERR_error_string_n(ERR_get_error(), errStr, sizeof(errStr));
	Nan::ThrowError(errStr);
}

#ifdef DEBUG
static void dumpBIO(BIO * bio) {
	BUF_MEM *bmem;
	BIO_get_mem_ptr(bio, &bmem);
	DEBUGLOG("%.*s\n", (int) bmem->length, bmem->data);
}

static void dumpHex(char * c, int n) {
	for (int i = 0; i < n; i++) {
		DEBUGLOG("%02hhx ", c[i]);
	}
	DEBUGLOG("\n");
}

static void dumpBIOHex(BIO * bio) {
	BUF_MEM *bmem;
	BIO_get_mem_ptr(bio, &bmem);
	dumpHex(bmem->data, (int) bmem->length);
}
#endif

static int generateCookie(SSL *ssl, unsigned char *cookie, unsigned int *cookieLen) {
	// Get remote peer information
	std::string * peer = (std::string*) SSL_get_ex_data(ssl, peerIdx);

	// Calc token using secret and peer information
	HMAC(
		EVP_sha1(),
		cookie_secret, COOKIE_SECRET_LENGTH,
		(const unsigned char*) peer->c_str(), peer->length(),
		cookie, cookieLen
	);

#ifdef DEBUG
	DEBUGLOG("PEER   %s\n", peer->c_str());
	DEBUGLOG("SECRET ");
	dumpHex((char *) cookie_secret, COOKIE_SECRET_LENGTH);
	DEBUGLOG("TOKEN  ");
	dumpHex((char *) cookie, (int) *cookieLen);
#endif

	return 1;
}

static int verifyCookie(SSL *ssl, unsigned char *cookie, unsigned int cookieLen) {
	int rc;
	unsigned char expectedCookie[EVP_MAX_MD_SIZE];
	unsigned int expectedCookieLen;

	// Calc expected cookie
	rc = generateCookie(ssl, expectedCookie, &expectedCookieLen);
	if (!rc) return 0;

	if (cookieLen == expectedCookieLen && memcmp(cookie, expectedCookie, cookieLen) == 0) {
		return 1;
	} else {
		return 0;
	}
}

class Server : public Nan::ObjectWrap {
public:
	static NAN_MODULE_INIT(Init) {
		v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
		tpl->SetClassName(Nan::New("Server").ToLocalChecked());
		tpl->InstanceTemplate()->SetInternalFieldCount(1);

		Nan::SetPrototypeMethod(tpl, "handlePacket", handlePacket); // clientKey, packet
		Nan::SetPrototypeMethod(tpl, "send", send); // clientKey, payload
		// Nan::SetPrototypeMethod(tpl, "getClientCert", getClientCert); // clientKey -> lookup via hash map

		constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
		Nan::Set(target, Nan::New("Server").ToLocalChecked(),
		Nan::GetFunction(tpl).ToLocalChecked());
	}

private:
	Nan::Callback cbEvent;
	Nan::Callback cbWrite;
	SSL_CTX *ctx;
	SSL *ssl;
	std::map<std::string, SSL*> connections;

	explicit Server(BIO *pkey, BIO *cert, BIO *ca, BIO *clica) : ctx(NULL), ssl(NULL) {
		int rc;

		// New DTLS1.2 context
		this->ctx = SSL_CTX_new(DTLSv1_2_server_method());
		if (this->ctx == NULL) throwGlobalSSLError();

		// Setup context
		// - Load certificate chain
		rc = readCertChain(this->ctx, cert);
		if (!rc) throwGlobalSSLError();
		// - Load private key
		rc = readPrivateKey(this->ctx, pkey);
		if (!rc) throwGlobalSSLError();
		// - Check whether private key and certificate belong to each other
		rc = SSL_CTX_check_private_key(this->ctx);
		if (!rc) throwGlobalSSLError();
		// - Read CAs
		// TODO
		// - Generate ECDHE key
		// TODO
		// - Set ciphers
		// TODO
		// - Register cookie factory
		SSL_CTX_set_cookie_generate_cb(this->ctx, generateCookie);
		SSL_CTX_set_cookie_verify_cb(this->ctx, verifyCookie);

		rc = sslFromCtx(this->ctx, &this->ssl);
		if (!rc) throwGlobalSSLError();
	}

	~Server() {}

	static NAN_METHOD(New) {
		// Read arguments
		BIO *pkey = arg2bio(NULL, info, 0);
		BIO *cert = arg2bio(NULL, info, 1);
		BIO *ca = arg2bio(NULL, info, 2);
		BIO *clica = arg2bio(NULL, info, 3);

		// Create new SSL context
		Server *obj = new Server(pkey, cert, ca, clica);
		obj->cbEvent.Reset(info[5].As<v8::Function>());
		obj->cbWrite.Reset(info[6].As<v8::Function>());

		// Free local ressources
		BIO_free(pkey);
		BIO_free(cert);
		BIO_free(ca);
		BIO_free(clica);

		// Return handle to instance
		obj->Wrap(info.This());
		info.GetReturnValue().Set(info.This());
	}

	void sendData(SSL * ssl) {
		// Check whether data is waiting for be sent
		BIO * wbio = SSL_get_wbio(ssl);
		DEBUGLOG("PENDING %d\n", BIO_ctrl_pending(wbio));
		if (BIO_ctrl_pending(wbio) == 0) return;

		// Fetch peer identifier
		std::string * peer = (std::string*) SSL_get_ex_data(ssl, peerIdx);

		// Read output data
		char packet[4096];
		int n = BIO_read(wbio, packet, sizeof(packet));

		// Call send callback
		Nan::MaybeLocal<v8::Object> jsPacket = Nan::NewBuffer(packet, n);
		Nan::MaybeLocal<v8::String> jsPeer = Nan::New<v8::String>(peer->c_str());
		v8::Local<v8::Value> argv[] = {jsPeer.ToLocalChecked(), jsPacket.ToLocalChecked()};
		this->cbWrite.Call(2, argv);
	}

	void sendEvent(std::string * peer, const char * event, char * data, int n) {
		Nan::MaybeLocal<v8::String> jsPeer = Nan::New<v8::String>(peer->c_str());
		Nan::MaybeLocal<v8::String> jsEvent = Nan::New<v8::String>(event);
		if (data == NULL) {
			v8::Local<v8::Value> argv[] = {
				jsPeer.ToLocalChecked(),
				jsEvent.ToLocalChecked()
			};
			this->cbEvent.Call(2, argv);
		} else {
			Nan::MaybeLocal<v8::Object> jsData = Nan::NewBuffer(data, n);
			v8::Local<v8::Value> argv[] = {
				jsPeer.ToLocalChecked(),
				jsEvent.ToLocalChecked(),
				jsData.ToLocalChecked()
			};
			this->cbEvent.Call(3, argv);
		}
	}

	static NAN_METHOD(handlePacket) {
		v8::String::Utf8Value peerStr(info[0]->ToString());
		std::string peer = std::string(*peerStr);
		Server* obj = Nan::ObjectWrap::Unwrap<Server>(info.Holder());
		SSL *candidate;

		// Search SSL candidate
		if (obj->connections.find(peer) != obj->connections.end()) {
			// The peer is known to us
			DEBUGLOG("Talking to friend %s\n", peer.c_str());
			candidate = obj->connections[peer];
		} else {
			// The peer is unknown -> try to shake hands
			DEBUGLOG("Talking to stranger %s\n", peer.c_str());
			candidate = obj->ssl;
			std::string * candidatePeer = (std::string*) SSL_get_ex_data(candidate, peerIdx);
			candidatePeer->assign(peer);
		}

		// Copy data to candidate's rbio
		arg2bio(SSL_get_rbio(candidate), info, 1);

		// Depending on the candidate's state we call the right function
		if (!SSL_is_init_finished(candidate)) {
			int rc = SSL_do_handshake(candidate);
			if (rc == 2) {
				// We recieved a valid cookie! -> Create a new context
				obj->connections.insert(std::pair<std::string, SSL*>(peer, candidate));
				sslFromCtx(obj->ctx, &obj->ssl);
				obj->sendEvent(&peer, "handshake", NULL, 0);
			} else if (rc == 1) {
				obj->sendEvent(&peer, "connected", NULL, 0);
			}
		} else {
			char buffer[4096];
			int rc = SSL_read(candidate, buffer, sizeof(buffer));
			if (rc <= 0 && SSL_get_error(candidate, rc) == SSL_ERROR_ZERO_RETURN) {
				// Disconnected!
				SSL_shutdown(candidate);
				obj->sendEvent(&peer, "shutdown", NULL, 0);
			} else if (rc > 0) {
				// Call message callback if we received data
				obj->sendEvent(&peer, "message", buffer, rc);
			}
		}

		// Call write callback
		obj->sendData(candidate);

		// If we sent shutdown event to connected client, clear all related data
		if (candidate != obj->ssl && SSL_get_shutdown(candidate) & SSL_SENT_SHUTDOWN) {
			DEBUGLOG("Removing friend %s\n", peer.c_str());
			SSL_free(candidate);
			obj->connections.erase(peer);
			DEBUGLOG("Left connections: %lu\n", obj->connections.size());
			obj->sendEvent(&peer, "remove", NULL, 0);
		}
	}

	static NAN_METHOD(send) {
		v8::String::Utf8Value peerStr(info[0]->ToString());
		std::string peer = std::string(*peerStr);
		Server* obj = Nan::ObjectWrap::Unwrap<Server>(info.Holder());
		v8::Local<v8::Object> buffer = info[1]->ToObject();

		// Make sure peer exists
		if (obj->connections.find(peer) == obj->connections.end()) return;

		SSL * ssl = obj->connections[peer];
		int rc = SSL_write(ssl, node::Buffer::Data(buffer), node::Buffer::Length(buffer));
		DEBUGLOG("Sent %d bytes to %s\n", rc, peer.c_str());
		// TODO: Check whether write was successful! Otherwise data will be lost.

		// Call write callback
		obj->sendData(ssl);
	}

	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

NAN_MODULE_INIT(Init) {
	SSL_load_error_strings ();
	SSL_library_init ();

	DEBUGLOG("Version: %s\n", SSLeay_version(SSLEAY_VERSION));

	// Generate secret for tokens
	if (RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH) <= 0) {
		Nan::ThrowError("Generating cookie secret failed");
	}

	// Register ex data stores
	peerIdx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	if (peerIdx < 0) {
		Nan::ThrowError("Generating ex data store failed");
	}

	Server::Init(target);
}

NODE_MODULE(dlts, Init)
