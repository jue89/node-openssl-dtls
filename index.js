const Server = require('./server.js');
const Peer = require('./peer.js');

const createServer = (opts) => new Server(opts);

module.exports = {
	Server,
	Peer,
	createServer
};
