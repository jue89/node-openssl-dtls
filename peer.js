const EventEmitter = require('events').EventEmitter;
const DTLS = require('./dtls_wrapper.js');

class Peer extends EventEmitter {
	constructor (server, rinfo) {
		super();

		this.rinfo = rinfo;
		this.suppressRetransmitsQuirk = server.suppressRetransmitsQuirk;
		this.blockOutgress = false;

		const onSend = (datagram) => {
			if (this.blockOutgress) return;
			server.socket.send(datagram, 0, datagram.length, rinfo.port, rinfo.address);
		};

		const onMessage = (message) => {
			this._resetDestroyTimer(server.connectionTimeout);
			this.emit('message', message);
		};

		const onConnected = () => {
			this._resetDestroyTimer(server.connectionTimeout);
			this.emit('secureConnection');
		};

		const onError = (err) => {
			this._destroy(new Error(err));
		};

		const onShutdown = () => {
			this.end();
		};

		const getRetransmitTimeout = (last) => {
			const next = server.getRetransmitTimeout(last);
			return next;
		};

		this.session = new DTLS.Session(
			server.ctx,
			server.cookieSecretPRF.fetch(16),
			server.mtu,
			onSend,
			onMessage,
			onConnected,
			onError,
			onShutdown,
			getRetransmitTimeout
		);

		this._resetDestroyTimer(server.handshakeTimeout);
	}

	_handler (data) {
		// Clear timer
		if (this.toResend) clearTimeout(this.toResend);

		// If we shall be quirky, suppress any packets that are not a
		// reaction on ingress packets.
		if (this.suppressRetransmitsQuirk && data === undefined) this.blockOutgress = true;

		const toResend = (data) ? this.session.handler(data) : this.session.handler();

		this.blockOutgress = false;

		// The handler returns the amount of remaining
		// millisconds until a retransmit shall happen.
		// Or 0 if no timers has been started.
		if (toResend) {
			this.toResend = setTimeout(() => this._handler(), toResend);
		}
	}

	_resetDestroyTimer (delay) {
		if (this.toDestroy) clearTimeout(this.toDestroy);
		if (delay) this.toDestroy = setTimeout(() => this.end(), delay);
	}

	address () {
		return this.rinfo;
	}

	getCertChain () {
		return this.session.getPeerCert();
	}

	_destroy (err) {
		if (!this.session) return;

		// Clear timer
		if (this.toResend) clearTimeout(this.toResend);
		this._resetDestroyTimer();

		// Clear session
		if (err) {
			this.emit('error', err);
		} else {
			this.session.close();
		}
		delete this.session;

		this.emit('close');
	}

	end () {
		this._destroy();
	}

	send (message) {
		this.session.send(message);
	}
}

module.exports = Peer;
