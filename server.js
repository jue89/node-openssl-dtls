const events = require('events');
const dgram = require('dgram');
const util = require('util');
const dtls = require('./build/Release/dtls.node');

const knownPeers = {};

const string2peer = (peer) => {
	if (knownPeers[peer] === undefined) {
		const tmp = peer.split(' ');
		if (tmp.length !== 3) return;
		knownPeers[peer] = {
			family: tmp[0],
			address: tmp[1],
			port: parseInt(tmp[2])
		};
	}
	return knownPeers[peer];
};

const peer2string = (peer) => `${peer.family} ${peer.address} ${peer.port}`;

function Peer (server, peerStr) {
	events.EventEmitter.call(this);
	this.server = server;
	this.peerStr = peerStr;
}

util.inherits(Peer, events.EventEmitter);

Peer.prototype.address = function () {
	return string2peer(this.peerStr);
};

Peer.prototype.send = function (message) {
	console.log(this.server.backend);
	this.server.backend.send(this.peerStr, message);
};

function Server (opts) {
	events.EventEmitter.call(this);

	// Store for connected peers
	this.peers = {};

	// Create new socket or take the provided one
	const socket = opts.socket || dgram.createSocket({ type: 'udp6' });

	// Calc the correct verify mode
	let verifyMode = 0;
	if (opts.requestCert) {
		verifyMode = 1;
		if (opts.rejectUnauthorized) {
			verifyMode = 2;
		}
	}

	// Event listeners for events created by openSSL
	const onEvent = (peerStr, eventName, data) => {
		switch (eventName) {
			case 'handshake':
				this.emit('connection', string2peer(peerStr));
				break;
			case 'connected':
				this.peers[peerStr] = new Peer(this, peerStr);
				setImmediate(() => this.emit('secureConnection', this.peers[peerStr]));
				break;
			case 'message':
				this.peers[peerStr].emit('message', Buffer.from(data));
				break;
			case 'shutdown':
				this.peers[peerStr].emit('close');
				break;
			case 'remove':
				delete this.peers[peerStr];
				break;
		}
	};

	// Listener for encrypted data from openSSL
	const onData = (peerStr, packet) => {
		const peer = string2peer(peerStr);
		socket.send(Buffer.from(packet), 0, packet.length, peer.port, peer.address);
	};

	this.backend = new dtls.Server(
		opts.key,
		opts.cert,
		opts.ca,
		verifyMode,
		opts.ciphers || '', // Ciphers
		onEvent,
		onData
	);

	// Forward incoming packages to openSSL
	socket.on('message', (packet, peer) => this.backend.handlePacket(peer2string(peer), packet));

	// Listen on given port
	socket.bind(opts.port);
}

util.inherits(Server, events.EventEmitter);

module.exports = Server;
