module.exports.Context = jest.fn(function () {
	this.setCiphers = jest.fn();
	this.setCertAndKey = jest.fn();
	this.setCA = jest.fn();
	this.setVerifyLevel = jest.fn();
});

module.exports.Session = jest.fn(function (a, b, c, onSend, onMessage, onConnected, onError, onShutdown) {
	this.onSend = onSend;
	this.onMessage = onMessage;
	this.onConnected = onConnected;
	this.onError = onError;
	this.onShutdown = onShutdown;
	this.handler = jest.fn(() => 0);
	this.getPeerCert = jest.fn(() => Buffer.alloc(0));
	this.close = jest.fn();
	this.send = jest.fn();
});
