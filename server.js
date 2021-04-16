const DTLS = require('./dtls_wrapper.js');
const dgram = require('dgram');
const crypto = require('crypto');
const EventEmitter = require('events').EventEmitter;
const PrfSHA256 = require('./helper/prf_sha256.js');
const Peer = require('./peer.js');

class Server extends EventEmitter {
	constructor (opts) {
		super();

		// Check for mandatory paramters
		if (!opts.key) throw new Error('Option key is mandatory');
		if (!opts.cert) throw new Error('Option cert is mandatory');

		// Set defaults
		// Default MTU: 1500B ETH MTU - 40B IPv6 Header - 8B UDP Header = 1452B
		this.mtu = opts.mtu || 1452;
		this.handshakeTimeout = opts.handshakeTimeout || 30000;
		this.connectionTimeout = opts.connectionTimeout || 600000;
		this.suppressRetransmitsQuirk = opts.suppressRetransmitsQuirk || false;
		this.getRetransmitTimeout = opts.retransmitTimeout || 1000000; // 1s by default
		if (typeof this.getRetransmitTimeout === 'number') {
			const firstTimeout = this.getRetransmitTimeout;
			this.getRetransmitTimeout = (last) => (last) ? last * 2 : firstTimeout;
		}

		// Convert verify level
		let verifyLevel = 0;
		if (opts.requestCert) verifyLevel = 1;
		if (opts.rejectUnauthorized) verifyLevel = 2;

		// Create socket
		this.socket = opts.socket || dgram.createSocket('udp6');

		// Create context
		this.ctx = new DTLS.Context();
		this.ctx.setCertAndKey(opts.cert, opts.key);
		this.ctx.setVerifyLevel(verifyLevel);
		if (opts.ca) this.ctx.setCA(opts.ca);
		if (opts.ciphers) this.ctx.setCiphers(opts.ciphers);

		// Create cookie PRF
		this.cookieSecretPRF = new PrfSHA256(crypto.randomBytes(32), 'dtls-server');

		// Create store for peers
		this.peers = {};

		// Listen for datagrams
		this.socket.on('message', (message, rinfo) => {
			const key = `${rinfo.address} ${rinfo.port}`;

			// New connection
			if (!this.peers[key]) {
				const peer = new Peer(this, rinfo);
				this.peers[key] = peer;
				peer.once('close', () => {
					delete this.peers[key];
				}).once('secureConnection', () => {
					this.emit('secureConnection', peer);
				}).once('error', (err) => {
					this.emit('error', err, rinfo);
				});
				this.emit('connection', rinfo);
			}

			this.peers[key]._handler(message);
		});
	}

	bind () {
		const args = Array.prototype.slice.call(arguments);
		this.socket.bind.apply(this.socket, args);
	}

	close (cb) {
		Object.keys(this.peers).forEach((key) => this.peers[key].end());
		this.socket.close(cb);
		delete this.ctx;
	}
}

module.exports = Server;
