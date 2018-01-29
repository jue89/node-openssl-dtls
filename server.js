'use strict';

const events = require('events');
const dgram = require('dgram');
const util = require('util');
const dtls = require('./build/Release/dtls.node');

const string2peer = (peer) => {
	const tmp = peer.split(' ');
	if (tmp.length !== 2) return;
	return {
		address: tmp[0],
		port: parseInt(tmp[1])
	};
};

const peer2string = (peer) => `${peer.address} ${peer.port}`;

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
	if (!(message instanceof Buffer)) throw new Error('message must be an instance of Buffer');
	this.server.backend.send(this.peerStr, message);
};

Peer.prototype.getCertChain = function () {
	return Buffer.from(this.server.backend.getPeerCert(this.peerStr));
};

Peer.prototype.end = function () {
	this.server.backend.shutdown(this.peerStr);
};

function Server (opts) {
	events.EventEmitter.call(this);

	// Store MTU of the datagram.
	// Default MTU: 1500B ETH MTU - 40B IPv6 Header - 8B UDP Header = 1452B
	this.mtu = opts.mtu || 1452;

	// Store for connected peers
	this.peers = {};

	// Create new socket or take the provided one
	this.socket = opts.socket || dgram.createSocket({ type: 'udp6' });

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
				process.nextTick(() => this.emit('secureConnection', this.peers[peerStr]));
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
			case 'error':
				this.emit('error', new Error(data.toString()), string2peer(peerStr));
		}
	};

	// Listener for encrypted data from openSSL
	const getRecordLength = (buffer, offset) => buffer.readUInt16BE(offset + 11) + 13;
	const onData = (peerStr, packet) => {
		packet = Buffer.from(packet);
		const peer = string2peer(peerStr);
		let remaining = packet.length;
		let offset = 0;
		while (remaining > 0) {
			// Collect as many records as possible fitting in one datagram.
			// Always include the first record! If it exceeds the MTU try to transmit
			// it anyway. Maybe some IP fragmentation magic can handle this.
			let length = getRecordLength(packet, offset);
			while (remaining > length) {
				// Read the length in byte of the next record
				let tmp = getRecordLength(packet, offset + length);
				if (length + tmp <= this.mtu) {
					// If the records fits into MTU, add its length to the datagram length.
					length += tmp;
				} else {
					// Break if the next record wouldn't fit in the current datagram.
					break;
				}
			}
			// Send the datagram
			this.socket.send(packet, offset, length, peer.port, peer.address);
			remaining -= length;
			offset += length;
		}
	};

	this.backend = new dtls.Server(
		opts.key,
		opts.cert,
		opts.ca,
		verifyMode,
		opts.ciphers,
		onEvent,
		onData,
		this.mtu
	);

	// Forward incoming packages to openSSL
	this.acceptDatagrams = true;
	this.socket.on('message', (packet, peer) => {
		if (!this.acceptDatagrams) return;
		this.backend.handlePacket(peer2string(peer), packet);
	});

	// Expose bind method
	const that = this;
	this.bind = function () {
		const args = Array.prototype.slice.call(arguments);
		that.socket.bind.apply(that.socket, args);
	};
}

util.inherits(Server, events.EventEmitter);

Server.prototype.close = function (cb) {
	// "Unbind" message callback
	this.acceptDatagrams = false;

	// Cleanup DTLS context
	this.backend.destroy();

	// Close socket
	process.nextTick(() => this.socket.close(cb));
};

module.exports = Server;
