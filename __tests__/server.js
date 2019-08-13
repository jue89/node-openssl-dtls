/* eslint no-new: "off" */

const EventEmitter = require('events').EventEmitter;

jest.mock('../dtls_wrapper.js');
const mockDTLS = require('../dtls_wrapper.js');

jest.mock('dgram');
const mockDgram = require('dgram');

jest.mock('crypto');
const mockCrypto = require('crypto');

jest.mock('../helper/prf_sha256.js');
const mockPrfSHA256 = require('../helper/prf_sha256.js');

jest.mock('../peer.js');
const mockPeer = require('../peer.js');

const Server = require('../server.js');

test('expect key', () => {
	try {
		new Server({
			cert: Buffer.alloc(0)
		});
		throw new Error('Failed!');
	} catch (e) {
		expect(e.message).toEqual('Option key is mandatory');
	}
});

test('expect cert', () => {
	try {
		new Server({
			key: Buffer.alloc(0)
		});
		throw new Error('Failed!');
	} catch (e) {
		expect(e.message).toEqual('Option cert is mandatory');
	}
});

test('set default MTU', () => {
	const opts = {
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0)
	};
	const s = new Server(opts);
	expect(s.mtu).toBe(1452);
});

test('set own MTU', () => {
	const opts = {
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0),
		mtu: 123
	};
	const s = new Server(opts);
	expect(s.mtu).toBe(123);
});

test('set default handshake timeout', () => {
	const opts = {
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0)
	};
	const s = new Server(opts);
	expect(s.handshakeTimeout).toBe(30 * 1000);
});

test('set own handshake timeout', () => {
	const opts = {
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0),
		handshakeTimeout: 123
	};
	const s = new Server(opts);
	expect(s.handshakeTimeout).toBe(123);
});

test('set default connection timeout', () => {
	const opts = {
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0)
	};
	const s = new Server(opts);
	expect(s.connectionTimeout).toBe(10 * 60 * 1000);
});

test('set own connection timeout', () => {
	const opts = {
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0),
		connectionTimeout: 123
	};
	const s = new Server(opts);
	expect(s.connectionTimeout).toBe(123);
});

test('create socket', () => {
	new Server({
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0)
	});
	expect(mockDgram.createSocket.mock.calls[0][0]).toEqual('udp6');
});

test('use own socket', () => {
	new Server({
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0),
		socket: new EventEmitter()
	});
	expect(mockDgram.createSocket.mock.calls.length).toBe(0);
});

test('create SSL context', () => {
	const s = new Server({
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0)
	});
	expect(s.ctx).toBeInstanceOf(mockDTLS.Context);
});

test('set key and cert', () => {
	const key = Buffer.alloc(0);
	const cert = Buffer.alloc(0);
	const s = new Server({key, cert});
	expect(s.ctx.setCertAndKey.mock.calls[0][0]).toBe(cert);
	expect(s.ctx.setCertAndKey.mock.calls[0][1]).toBe(key);
});

test('set ca', () => {
	const ca = Buffer.alloc(0);
	const s = new Server({key: Buffer.alloc(0), cert: Buffer.alloc(0), ca});
	expect(s.ctx.setCA.mock.calls[0][0]).toBe(ca);
});

test('set ciphers', () => {
	const ciphers = 'abc';
	const s = new Server({key: Buffer.alloc(0), cert: Buffer.alloc(0), ciphers});
	expect(s.ctx.setCiphers.mock.calls[0][0]).toBe(ciphers);
});

test('set verify: none', () => {
	const s = new Server({
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0),
		requestCert: false,
		rejectUnauthorized: false
	});
	expect(s.ctx.setVerifyLevel.mock.calls[0][0]).toBe(0);
});

test('set verify: request cert', () => {
	const s = new Server({
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0),
		requestCert: true,
		rejectUnauthorized: false
	});
	expect(s.ctx.setVerifyLevel.mock.calls[0][0]).toBe(1);
});

test('set verify: reject unauthorized', () => {
	const s = new Server({
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0),
		requestCert: true,
		rejectUnauthorized: true
	});
	expect(s.ctx.setVerifyLevel.mock.calls[0][0]).toBe(2);
});

test('generate cookie PRF', () => {
	const s = new Server({
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0)
	});
	expect(s.cookieSecretPRF).toBeInstanceOf(mockPrfSHA256);
	expect(mockPrfSHA256.mock.calls[0][0]).toBe(mockCrypto.randomBytes.mock.results[0].value);
	expect(mockCrypto.randomBytes.mock.calls[0][0]).toBe(32);
	expect(mockPrfSHA256.mock.calls[0][1]).toEqual('dtls-server');
});

test('create new peer', () => {
	const s = new Server({
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0)
	});
	const onConnection = jest.fn();
	s.on('connection', onConnection);
	const packet = Buffer.alloc(0);
	const rinfo = {address: 'abc', port: 123};
	mockDgram.createSocket.mock.results[0].value.emit('message', packet, rinfo);
	expect(mockPeer.mock.calls[0][0]).toBe(s);
	expect(mockPeer.mock.calls[0][1]).toBe(rinfo);
	expect(onConnection.mock.calls[0][0]).toBe(rinfo);
	expect(mockPeer.mock.instances[0]._handler.mock.calls[0][0]).toBe(packet);
});

test('send packets to exisiting peer', () => {
	new Server({
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0)
	});
	const packet0 = Buffer.alloc(0);
	const packet1 = Buffer.alloc(0);
	const rinfo = {address: 'abc', port: 123};
	mockDgram.createSocket.mock.results[0].value.emit('message', packet0, rinfo);
	mockDgram.createSocket.mock.results[0].value.emit('message', packet1, rinfo);
	expect(mockPeer.mock.calls.length).toBe(1);
	expect(mockPeer.mock.instances[0]._handler.mock.calls[0][0]).toBe(packet0);
	expect(mockPeer.mock.instances[0]._handler.mock.calls[1][0]).toBe(packet1);
});

test('propagate secureConnection events', () => {
	const s = new Server({
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0)
	});
	const onSecureConnection = jest.fn();
	s.on('secureConnection', onSecureConnection);
	const rinfo = {address: 'abc', port: 123};
	mockDgram.createSocket.mock.results[0].value.emit('message', Buffer.alloc(0), rinfo);
	mockPeer.mock.instances[0].emit('secureConnection');
	expect(onSecureConnection.mock.calls[0][0]).toBe(mockPeer.mock.instances[0]);
});

test('propagate error events', () => {
	const s = new Server({
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0)
	});
	const onError = jest.fn();
	s.on('error', onError);
	const rinfo = {address: 'abc', port: 123};
	mockDgram.createSocket.mock.results[0].value.emit('message', Buffer.alloc(0), rinfo);
	const err = new Error();
	mockPeer.mock.instances[0].emit('error', err);
	expect(onError.mock.calls[0][0]).toBe(err);
	expect(onError.mock.calls[0][1]).toBe(rinfo);
});

test('remove closed peers', () => {
	const s = new Server({
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0)
	});
	expect(Object.keys(s.peers).length).toBe(0);
	mockDgram.createSocket.mock.results[0].value.emit('message', Buffer.alloc(0), {address: 'abc', port: 123});
	expect(Object.keys(s.peers).length).toBe(1);
	mockPeer.mock.instances[0].emit('close');
	expect(Object.keys(s.peers).length).toBe(0);
});

test('close server', () => {
	const s = new Server({
		key: Buffer.alloc(0),
		cert: Buffer.alloc(0)
	});
	mockDgram.createSocket.mock.results[0].value.emit('message', Buffer.alloc(0), {address: 'abc', port: 123});
	const onClose = () => {};
	s.close(onClose);
	expect(mockDgram.createSocket.mock.results[0].value.close.mock.calls[0][0]).toBe(onClose);
	expect(mockPeer.mock.instances[0].end.mock.calls.length).toBe(1);
	expect(s.ctx).toBeUndefined();
});
