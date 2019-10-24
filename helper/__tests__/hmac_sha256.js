jest.mock('crypto');
const mockCrypto = require('crypto');

const HmacSHA256 = require('../hmac_sha256.js');

test('Calc HMAC over one block', () => {
	const secret = 'secret';
	const data = 'abc';
	const digest = Buffer.alloc(32, 'a');
	mockCrypto.Hmac.prototype.digest.mockReturnValue(digest);
	const ret = HmacSHA256(secret, data);
	expect(mockCrypto.createHmac.mock.calls[0][0]).toEqual('sha256');
	expect(mockCrypto.createHmac.mock.calls[0][1]).toBe(secret);
	expect(mockCrypto.Hmac.prototype.update.mock.calls.length).toBe(1);
	expect(mockCrypto.Hmac.prototype.update.mock.calls[0][0]).toBe(data);
	expect(ret).toBe(digest);
});

test('Calc HMAC over may blocks', () => {
	const data1 = 'abc';
	const data2 = 'def';
	HmacSHA256('secret', [data1, data2]);
	expect(mockCrypto.Hmac.prototype.update.mock.calls.length).toBe(2);
	expect(mockCrypto.Hmac.prototype.update.mock.calls[0][0]).toBe(data1);
	expect(mockCrypto.Hmac.prototype.update.mock.calls[1][0]).toBe(data2);
});
