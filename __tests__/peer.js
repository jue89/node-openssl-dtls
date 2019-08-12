/* eslint no-new: "off" */

jest.useFakeTimers();
afterEach(() => jest.clearAllTimers());

jest.mock('../dtls_wrapper.js');
const mockDTLS = require('../dtls_wrapper.js');

jest.mock('dgram');
const mockDgram = require('dgram');

const Peer = require('../peer.js');

test('create new session', () => {
	const ctx = {};
	const mtu = 123;
	const cookieSecretPRF = { fetch: jest.fn(() => Buffer.alloc(0)) };
	const s = new Peer({ctx, mtu, cookieSecretPRF}, {});
	expect(cookieSecretPRF.fetch.mock.calls[0][0]).toBe(16);
	expect(mockDTLS.Session.mock.calls[0][0]).toBe(ctx);
	expect(mockDTLS.Session.mock.calls[0][1]).toBe(cookieSecretPRF.fetch.mock.results[0].value);
	expect(mockDTLS.Session.mock.calls[0][2]).toBe(mtu);
	expect(s.session).toBe(mockDTLS.Session.mock.instances[0]);
});

test('return rinfo', () => {
	const rinfo = {};
	const s = new Peer({ctx: {}, mtu: 1, cookieSecretPRF: {fetch: () => {}}}, rinfo);
	expect(s.address()).toBe(rinfo);
});

test('proxy getCertChain call', () => {
	const s = new Peer({ctx: {}, mtu: 1, cookieSecretPRF: {fetch: () => {}}}, {});
	expect(s.getCertChain()).toBe(mockDTLS.Session.mock.instances[0].getPeerCert.mock.results[0].value);
});

test('proxy send call', () => {
	const s = new Peer({ctx: {}, mtu: 1, cookieSecretPRF: {fetch: () => {}}}, {});
	const data = Buffer.alloc(0);
	s.send(data);
	expect(mockDTLS.Session.mock.instances[0].send.mock.calls[0][0]).toBe(data);
});

test('send data to remote peer', () => {
	const address = 'abc';
	const port = 123;
	const socket = mockDgram.createSocket();
	new Peer({ctx: {}, mtu: 1, cookieSecretPRF: {fetch: () => {}}, socket}, {address, port});
	const data = Buffer.alloc(12);
	mockDTLS.Session.mock.instances[0].onSend(data);
	expect(socket.send.mock.calls[0][0]).toBe(data);
	expect(socket.send.mock.calls[0][1]).toBe(0);
	expect(socket.send.mock.calls[0][2]).toBe(data.length);
	expect(socket.send.mock.calls[0][3]).toBe(port);
	expect(socket.send.mock.calls[0][4]).toBe(address);
});

test('close connection', () => {
	const s = new Peer({ctx: {}, mtu: 1, cookieSecretPRF: {fetch: () => {}}}, {});
	const onClose = jest.fn();
	s.on('close', onClose);
	expect(s.session).toBeDefined();
	s.end();
	expect(s.session).toBeUndefined();
	expect(onClose.mock.calls.length).toBe(1);
	expect(mockDTLS.Session.mock.instances[0].close.mock.calls.length).toBe(1);
});

test('emit messages', () => {
	const s = new Peer({ctx: {}, mtu: 1, cookieSecretPRF: {fetch: () => {}}}, {});
	const onMessage = jest.fn();
	s.on('message', onMessage);
	const msg = Buffer.alloc(0);
	mockDTLS.Session.mock.instances[0].onMessage(msg);
	expect(onMessage.mock.calls[0][0]).toBe(msg);
});

test('emit secureConnection', () => {
	const s = new Peer({ctx: {}, mtu: 1, cookieSecretPRF: {fetch: () => {}}}, {});
	const onSecureConnection = jest.fn();
	s.on('secureConnection', onSecureConnection);
	mockDTLS.Session.mock.instances[0].onConnected();
	expect(onSecureConnection.mock.calls.length).toBe(1);
});

test('emit error', () => {
	const s = new Peer({ctx: {}, mtu: 1, cookieSecretPRF: {fetch: () => {}}}, {});
	const onError = jest.fn();
	s.on('error', onError);
	const message = 'fckup';
	s.end = jest.fn();
	mockDTLS.Session.mock.instances[0].onError(message);
	expect(onError.mock.calls[0][0]).toBeInstanceOf(Error);
	expect(onError.mock.calls[0][0].message).toBe(message);
	expect(s.end.mock.calls.length).toBe(1);
});

test('emit close', () => {
	const s = new Peer({ctx: {}, mtu: 1, cookieSecretPRF: {fetch: () => {}}}, {});
	s.end = jest.fn();
	mockDTLS.Session.mock.instances[0].onShutdown();
	expect(s.end.mock.calls.length).toBe(1);
});

test('handle incoming packets', () => {
	const s = new Peer({ctx: {}, mtu: 1, cookieSecretPRF: {fetch: () => {}}}, {});
	const packet = Buffer.alloc(0);
	s._handler(packet);
	expect(mockDTLS.Session.mock.instances[0].handler.mock.calls[0][0]).toBe(packet);
	expect(setTimeout.mock.calls.length).toBe(0);
});

test('setup resend timer', () => {
	const to = 123;
	const s = new Peer({ctx: {}, mtu: 1, cookieSecretPRF: {fetch: () => {}}}, {});
	mockDTLS.Session.mock.instances[0].handler.mockReturnValueOnce(to);
	const packet = Buffer.alloc(0);
	s._handler(packet);
	expect(mockDTLS.Session.mock.instances[0].handler.mock.calls.length).toBe(1);
	expect(mockDTLS.Session.mock.instances[0].handler.mock.calls[0][0]).toBe(packet);
	jest.advanceTimersByTime(to);
	expect(mockDTLS.Session.mock.instances[0].handler.mock.calls.length).toBe(2);
	expect(mockDTLS.Session.mock.instances[0].handler.mock.calls[1][0]).toBeUndefined();
});

test('clear resend timer', () => {
	const to = 123;
	const s = new Peer({ctx: {}, mtu: 1, cookieSecretPRF: {fetch: () => {}}}, {});
	mockDTLS.Session.mock.instances[0].handler.mockReturnValueOnce(to);
	mockDTLS.Session.mock.instances[0].handler.mockReturnValueOnce(0);
	const packet = Buffer.alloc(0);
	s._handler(packet);
	expect(mockDTLS.Session.mock.instances[0].handler.mock.calls.length).toBe(1);
	jest.advanceTimersByTime(to - 1);
	s._handler(packet);
	jest.advanceTimersByTime(1);
	expect(mockDTLS.Session.mock.instances[0].handler.mock.calls.length).toBe(2);
});

test('setup initial destroy timer', () => {
	const handshakeTimeout = 123;
	const connectionTimeout = 456;
	const s = new Peer({ctx: {}, mtu: 1, cookieSecretPRF: {fetch: () => {}}, handshakeTimeout, connectionTimeout}, {});
	const onClose = jest.fn();
	s.on('close', onClose);
	jest.advanceTimersByTime(handshakeTimeout);
	expect(onClose.mock.calls.length).toBe(1);
});

test('set connection destroy timer', () => {
	const handshakeTimeout = 456;
	const connectionTimeout = 123;
	const s = new Peer({ctx: {}, mtu: 1, cookieSecretPRF: {fetch: () => {}}, handshakeTimeout, connectionTimeout}, {});
	const onClose = jest.fn();
	s.on('close', onClose);
	mockDTLS.Session.mock.instances[0].onConnected();
	jest.advanceTimersByTime(connectionTimeout);
	expect(onClose.mock.calls.length).toBe(1);
});

test('reset connection destroy timer', () => {
	const handshakeTimeout = 456;
	const connectionTimeout = 123;
	const s = new Peer({ctx: {}, mtu: 1, cookieSecretPRF: {fetch: () => {}}, handshakeTimeout, connectionTimeout}, {});
	const onClose = jest.fn();
	s.on('close', onClose);
	mockDTLS.Session.mock.instances[0].onConnected();
	jest.advanceTimersByTime(connectionTimeout - 1);
	mockDTLS.Session.mock.instances[0].onMessage();
	jest.advanceTimersByTime(1);
	expect(onClose.mock.calls.length).toBe(0);
});
