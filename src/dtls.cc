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

static int readCACerts(SSL_CTX * ctx, BIO * ca) {
	int rc = 1;
	X509_STORE * caStore;
	X509_LOOKUP * lu;
	STACK_OF(X509_INFO) * caInfo;

	// Empty CA -> skip
	if (!ca) goto final;

	caStore = SSL_CTX_get_cert_store(ctx);

	// Add lookup method
	lu = X509_STORE_add_lookup(caStore, X509_LOOKUP_file());
	if (lu == NULL) {
		rc = 0;
		goto final;
	}

	// Add CA certs to cert store
	caInfo = PEM_X509_INFO_read_bio(ca, NULL, noPasswordCallback, NULL);
	for (int i = 0; i < sk_X509_INFO_num(caInfo); i++) {
		X509_INFO *part = sk_X509_INFO_value(caInfo, i);
		if (part->x509) {
			DEBUGLOG("Adding CA cert: %s\n", part->x509->name);
			X509_STORE_add_cert(lu->store_ctx, part->x509);
			SSL_CTX_add_client_CA(ctx, part->x509);
		}
		if (part->crl) {
			DEBUGLOG("Adding CRL\n");
			X509_STORE_add_crl(lu->store_ctx, part->crl);
		}
	}
	sk_X509_INFO_pop_free(caInfo, X509_INFO_free);

final:
	return rc;
}

static int verifyCallback(int ok, X509_STORE_CTX *ctx) {
#ifdef DEBUG
	int err = X509_STORE_CTX_get_error(ctx);
	int depth = X509_STORE_CTX_get_error_depth(ctx);

	DEBUGLOG("depth=%d ", depth);
	DEBUGLOG("verify error:num=%d:%s\n", err, X509_verify_cert_error_string(err));
	DEBUGLOG("verify return:%d\n", ok);
#endif
	return ok;
}

static void setVerify(SSL_CTX * ctx, int verifyLevel) {
	int verifyMode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

	DEBUGLOG("Verify level: %d\n", verifyLevel);
	switch (verifyLevel) {
		case 0: verifyMode = SSL_VERIFY_NONE; break;
		case 1: verifyMode = SSL_VERIFY_PEER; break;
		case 2: verifyMode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT; break;
	}

	SSL_CTX_set_verify(ctx, verifyMode, verifyCallback);
}

static int generateECDHEKey(SSL_CTX * ctx) {
	EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (!SSL_CTX_set_tmp_ecdh(ctx, ecdh)) return 0;
	return 1;
}

static int sslFromCtx(SSL_CTX * ctx, SSL ** ssl, int mtu) {
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

	// Set MTU
	SSL_set_options(*ssl, SSL_OP_NO_QUERY_MTU);
	DTLS_set_link_mtu(*ssl, mtu);
	DEBUGLOG("MTU %d\n", mtu);

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
		Nan::SetPrototypeMethod(tpl, "getPeerCert", getPeerCert); // clientKey
		Nan::SetPrototypeMethod(tpl, "shutdown", shutdown); // clientKey
		Nan::SetPrototypeMethod(tpl, "destroy", destroy);

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
	int mtu;

	explicit Server(BIO *pkey, BIO *cert, BIO *ca, int verifyLevel, std::string * ciphers, int mtu) :
		ctx(NULL),
		ssl(NULL),
		mtu(mtu)
	{
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
		rc = readCACerts(this->ctx, ca);
		if (!rc) throwGlobalSSLError();
		// - Set handling of peer certificates
		setVerify(this->ctx, verifyLevel);
		// - Generate ECDHE key
		rc = generateECDHEKey(this->ctx);
		if (!rc) throwGlobalSSLError();
		// - Set ciphers
		if (ciphers->size()) {
			DEBUGLOG("Ciphers: %s\n", ciphers->c_str());
			rc = SSL_CTX_set_cipher_list(this->ctx, ciphers->c_str());
			if (!rc) throwGlobalSSLError();
		}
		// - Register cookie factory
		SSL_CTX_set_cookie_generate_cb(this->ctx, generateCookie);
		SSL_CTX_set_cookie_verify_cb(this->ctx, verifyCookie);

		// Create first SSL context
		rc = sslFromCtx(this->ctx, &this->ssl, this->mtu);
		if (!rc) throwGlobalSSLError();
	}

	~Server() {}

	static NAN_METHOD(New) {
		// Read arguments
		BIO *pkey = arg2bio(NULL, info, 0);
		BIO *cert = arg2bio(NULL, info, 1);
		BIO *ca = arg2bio(NULL, info, 2);
		int verifyLevel = (info[3]->ToInteger())->Value();
		std::string ciphers = std::string();
		if (!info[4]->IsUndefined()) {
			v8::String::Utf8Value ciphersStr(info[4]->ToString());
			ciphers.assign(*ciphersStr);
		}
		int mtu = (info[7]->ToInteger())->Value();

		// Create new SSL context
		Server *obj = new Server(pkey, cert, ca, verifyLevel, &ciphers, mtu);
		obj->cbEvent.Reset(info[5].As<v8::Function>());
		obj->cbWrite.Reset(info[6].As<v8::Function>());

		// Free local ressources
		BIO_free(pkey);
		BIO_free(cert);
		BIO_free(ca);

		// Return handle to instance
		obj->Wrap(info.This());
		info.GetReturnValue().Set(info.This());
	}

	void sendData(SSL * ssl) {
		// Check whether data is waiting for be sent
		BIO * wbio = SSL_get_wbio(ssl);
		if (BIO_ctrl_pending(wbio) == 0) return;

		// Fetch peer identifier
		std::string * peer = (std::string*) SSL_get_ex_data(ssl, peerIdx);

		// Read output data
		char * packet = (char*) malloc(4096);
		int n = BIO_read(wbio, packet, 4096);
		DEBUGLOG("OUT %d\n", n);

		// Call send callback
		Nan::MaybeLocal<v8::Object> jsPacket = Nan::NewBuffer(packet, n);
		Nan::MaybeLocal<v8::String> jsPeer = Nan::New<v8::String>(peer->c_str());
		v8::Local<v8::Value> argv[] = {jsPeer.ToLocalChecked(), jsPacket.ToLocalChecked()};
		this->cbWrite.Call(2, argv);

		// If the current ssl context is not the listen context, and
		// we sent shutdown event to connected client, clear all related data.
		if (ssl == this->ssl) return;
		if ((SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN) || (SSL_get_state(ssl) == SSL_ST_ERR)) {
			DEBUGLOG("Removing friend %s\n", peer->c_str());
			SSL_free(ssl);
			this->connections.erase(*peer);
			DEBUGLOG("Left connections: %lu\n", this->connections.size());
			this->sendEvent(peer, "remove", NULL, 0);
			delete peer;
		}
	}

	void sendEvent(const std::string * peer, const char * event, char * data, int n) {
		Nan::MaybeLocal<v8::String> jsPeer = Nan::New<v8::String>(peer->c_str());
		Nan::MaybeLocal<v8::String> jsEvent = Nan::New<v8::String>(event);
		if (data == NULL) {
			v8::Local<v8::Value> argv[] = {
				jsPeer.ToLocalChecked(),
				jsEvent.ToLocalChecked()
			};
			this->cbEvent.Call(2, argv);
		} else {
			char * bufferData = (char*) malloc(n);
			memcpy(bufferData, data, n);
			Nan::MaybeLocal<v8::Object> jsData = Nan::NewBuffer(bufferData, n);
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
		again:
			int rc = SSL_do_handshake(candidate);
			if (rc == 2) {
				// We recieved a valid cookie! -> Create a new context
				obj->connections.insert(std::pair<std::string, SSL*>(peer, candidate));
				sslFromCtx(obj->ctx, &obj->ssl, obj->mtu);
				obj->sendEvent(&peer, "handshake", NULL, 0);
				goto again;
			} else if (rc == 1) {
				obj->sendEvent(&peer, "connected", NULL, 0);
			} else if (SSL_get_error(candidate, rc) == SSL_ERROR_SSL) {
				char errStr[256];
				ERR_error_string_n(ERR_get_error(), errStr, sizeof(errStr));
				obj->sendEvent(&peer, "error", errStr, strlen(errStr));
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

	static NAN_METHOD(getPeerCert) {
		v8::String::Utf8Value peerStr(info[0]->ToString());
		std::string peer = std::string(*peerStr);
		Server* obj = Nan::ObjectWrap::Unwrap<Server>(info.Holder());

		// Make sure peer exists
		if (obj->connections.find(peer) == obj->connections.end()) return;

		BIO * pem = BIO_new(BIO_s_mem());
		SSL * ssl = obj->connections[peer];

		// Get peer's certificate
		X509 * cert = SSL_get_peer_certificate(ssl);
		if (cert != NULL) PEM_write_bio_X509(pem, cert);

		// Get peer's remaining certificate chain
		STACK_OF(X509) * chain = SSL_get_peer_cert_chain(ssl);
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
		Nan::MaybeLocal<v8::Object> jsData = Nan::NewBuffer(data, n);
		info.GetReturnValue().Set(jsData.ToLocalChecked());
	}

	static NAN_METHOD(shutdown) {
		v8::String::Utf8Value peerStr(info[0]->ToString());
		std::string peer = std::string(*peerStr);
		Server* obj = Nan::ObjectWrap::Unwrap<Server>(info.Holder());

		// Make sure peer exists
		if (obj->connections.find(peer) == obj->connections.end()) return;

		// Send shutdown event to stated peer
		SSL * ssl = obj->connections[peer];
		SSL_shutdown(ssl);
		obj->sendEvent(&peer, "shutdown", NULL, 0);

		// Call write callback
		obj->sendData(ssl);
	}

	static NAN_METHOD(destroy) {
		Server* obj = Nan::ObjectWrap::Unwrap<Server>(info.Holder());

		// Close all existing connections
		for (std::map<std::string, SSL*>::iterator it = obj->connections.begin(); it != obj->connections.end(); ++it) {
			DEBUGLOG("Shutdown %s\n", it->first.c_str());
			SSL_shutdown(it->second);
			obj->sendEvent(&it->first, "shutdown", NULL, 0);
			obj->sendData(it->second);
		}

		// Close listening context
		SSL_free(obj->ssl);

		// Close SSL context
		SSL_CTX_free(obj->ctx);
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
