const events = require('events');

class Socket extends events.EventEmitter {
	constructor () {
		super();
		this.send = jest.fn();
		this.close = jest.fn();
	}
}

module.exports.Socket = Socket;
module.exports.createSocket = jest.fn(() => new Socket());
