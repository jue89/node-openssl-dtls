const HmacSHA256 = require('./hmac_sha256.js');

// Section 5 of RFC5246

class PrfSHA256 {
	constructor (secret, seed) {
		this.secret = (secret instanceof Buffer) ? secret : Buffer.from(secret);
		this.seed = (seed instanceof Buffer) ? seed : Buffer.from(seed);
		// A(0) = seed
		this.a = this.seed;
	}

	fetch (length) {
		const acc = [];
		let accLen = 0;
		while (accLen < length) {
			// A(i) = HMAC_SHA256(secret, A(i-1))
			this.a = HmacSHA256(this.secret, this.a);
			// P_SHA256(secet, seed) = HMAC_SHA256(secret, A(i) + seed)
			const chunk = HmacSHA256(this.secret, [this.a, this.seed]);
			accLen += chunk.length;
			acc.push(chunk);
		}
		const data = Buffer.concat(acc);
		return data.slice(0, length);
	}
}

module.exports = PrfSHA256;
