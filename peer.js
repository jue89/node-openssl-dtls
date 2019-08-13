const EventEmitter = require('events').EventEmitter;
const DTLS = require('./dtls_wrapper.js');

class Peer extends EventEmitter {
	constructor (server, rinfo) {
		super();

		this.rinfo = rinfo;

		const onSend = (datagram) => {
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
			this.emit('error', new Error(err));
			this.end();
		};

		const onShutdown = () => {
			this.end();
		};

		this.session = new DTLS.Session(
			server.ctx,
			server.cookieSecretPRF.fetch(16),
			server.mtu,
			onSend,
			onMessage,
			onConnected,
			onError,
			onShutdown
		);

		this._resetDestroyTimer(server.handshakeTimeout);
	}

	_handler (data) {
		// Clear timer
		if (this.toResend) clearTimeout(this.toResend);

		const toResend = (data) ? this.session.handler(data) : this.session.handler();

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

	end () {
		if (!this.session) return;

		// Clear timer
		if (this.toResend) clearTimeout(this.toResend);
		this._resetDestroyTimer();

		// Clear session
		this.session.close();
		delete this.session;

		this.emit('close');
	}

	send (message) {
		this.session.send(message);
	}
}

module.exports = Peer;
