'use strict';

const Server = require('./server.js');

const createServer = (opts) => new Server(opts);

module.exports = {
	Server,
	createServer
};
