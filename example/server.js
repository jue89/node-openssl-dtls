const DTLS = require('..');
const {readFileSync} = require('fs');
const {join} = require('path');
const srv = DTLS.createServer({
	key: readFileSync(join(__dirname, 'server.key.pem')),
	cert: readFileSync(join(__dirname, 'server.crt.pem')),
	ca: readFileSync(join(__dirname, 'client-ca.crt.pem')),
	requestCert: true,
	rejectUnauthorized: true
});

srv.bind(9000);
srv.on('error', console.log);
srv.on('secureConnection', (peer) => {
	console.log(`Connection from ${peer.address().address} port ${peer.address().port}`);
	peer.on('message', (msg) => {
		peer.send(msg);
	});
});
