# OpenSSL DTLS1.2 Bindings

This module enables your application to listen for incoming DTLS1.2 connections. It uses OpenSSL shipped with Node.js (i.e. OpenSSL 1.0.2 atm).

## API

```js
const DTLS = require('openssl-dtls');
const srv = DTLS.createServer(opts);
```

Spawns a new server. ```opts``` is an object:
 * ```key```: Buffer. The server's private key in PEM format. *Mandatory.*
 * ```cert```: Buffer. The server's certificate in PEM format. *Mandatory.*
 * ```ca```: Buffer. CA certificate for validation of client certificates. *Optional.*
 * ```requestCert```: Boolean. Request certificate from client. *Default: false.*
 * ```rejectUnauthorized```: Boolean. Reject invalid client certificates. *Default: false.*
 * ```mtu```: Number. The wire's MTU. *Default: 1500 Ethernet MTU - 40 IPv6 Header - 8 UDP Header = 1452.*
 * ```ciphers```: String. Allowed ciphers. Further details: [OpenSSL Cipher List Format](https://www.openssl.org/docs/man1.0.2/apps/ciphers.html#CIPHER-LIST-FORMAT). *Optional.*
 * ```socket```: Instances of ```dgram.Socket```. By default a new ```'udp6'``` dgram socket will be created.

### Class: Server

#### Method: bind()

```js
srv.bind(...);
```

Proxy method for the ```bind()``` method of the ```socket``` specified with ```DTLS.createServer()```. If you haven't specified anything, have a look into the documentation of UDP/Datagram.

#### Method: close()

```js
srv.close([cb]);
```

Shuts down the server and calls ```cb``` once the underlying socket has been closed.

#### Event: connection

```js
srv.on('connection', (info) => {...});
```

Is raised if a client has started a handshake. ```info```:
 * ```address```: Remote address.
 * ```port```: Remote port.

#### Event: connection

```js
srv.on('error', (err, info) => {...});
```

Is raised if something went wrong. ```err``` is an instance of Error. ```info```:
 * ```address```: Remote address.
 * ```port```: Remote port.

#### Event: secureConnection

```js
srv.on('connection', (peer) => {...});
```

Is raised once a handshake has been successfully finished. ```peer``` is an instance of Peer.


### Class: Peer

#### Method: address()

```js
const info = peer.address();
```

Returns the peers address. ```info```:
 * ```address```: Remote address.
 * ```port```: Remote port.

#### Method: getCertChain()

```js
const chain = peer.getCertChain();
```

Returns the peers certificate chain. ```chain``` is a Buffer containing the certificates in PEM format. If no certificates has been prensented by the client, ```chain``` is and empty Buffer.

#### Method: send()

```js
peer.send(message);
```

Sends ```message``` to the client. ```message``` has to be a Buffer.

#### Method: end()

```js
peer.end();
```

Closes connection to ```peer```.

#### Event: message

```js
peer.on('message', (message) => {...});
```

Is raised if a ```message``` has been received from ```peer```.


#### Event: close

```js
peer.on('close', () => {...});
```

Is raised if the connection to ```peer``` has been closed.
