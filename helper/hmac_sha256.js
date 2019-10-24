const crypto = require('crypto');

function HmacSHA256 (secret, data) {
	if (!Array.isArray(data)) data = [data];
	const hmac = crypto.createHmac('sha256', secret);
	data.forEach((d) => hmac.update(d));
	return hmac.digest();
}

module.exports = HmacSHA256;
