const util = require('util');
const events = require('events');

module.exports = jest.fn(function () {
	events.EventEmitter.call(this);
	this._handler = jest.fn();
	this.end = jest.fn();
});
util.inherits(module.exports, events.EventEmitter);
