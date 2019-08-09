jest.mock('../hmac_sha256.js');
const mockHmacSHA256 = require('../hmac_sha256.js');

const PrfSHA256 = require('../prf_sha256.js');

test('Store secret and seed', () => {
	const seed = Buffer.from('abc');
	const secret = Buffer.from('secret');
	const p = new PrfSHA256(secret, seed);
	expect(p.seed).toBe(seed);
	expect(p.secret).toBe(secret);
});

test('Convert secret and seed to Buffer', () => {
	const seed = 'abc';
	const secret = 'secret';
	const p = new PrfSHA256(secret, seed);
	expect(p.seed).toBeInstanceOf(Buffer);
	expect(p.secret).toBeInstanceOf(Buffer);
	expect(p.seed.toString()).toEqual(seed);
	expect(p.secret.toString()).toEqual(secret);
});

test('Start with A(0)=seed', () => {
	const p = new PrfSHA256('secret', 'abc');
	expect(p.a).toEqual(p.seed);
});

test('Get one full block', () => {
	const seed = Buffer.from('abc');
	const secret = Buffer.from('secret');
	const p = new PrfSHA256(secret, seed);
	const rnd = p.fetch(32);
	expect(mockHmacSHA256.mock.calls[0][0]).toBe(secret);
	expect(mockHmacSHA256.mock.calls[0][1]).toBe(seed);
	expect(mockHmacSHA256.mock.calls[1][0]).toBe(secret);
	expect(mockHmacSHA256.mock.calls[1][1][0]).toBe(mockHmacSHA256.mock.results[0].value);
	expect(mockHmacSHA256.mock.calls[1][1][1]).toBe(seed);
	expect(mockHmacSHA256.mock.calls.length).toBe(2);
	expect(rnd).toEqual(mockHmacSHA256.mock.results[1].value);
});

test('Get two full blocks', () => {
	const seed = Buffer.from('abc');
	const secret = Buffer.from('secret');
	const p = new PrfSHA256(secret, seed);
	const rnd = p.fetch(64);
	for (let i = 0; i < 4; i += 2) {
		const a = (i === 0) ? seed : mockHmacSHA256.mock.results[i - 2].value;
		expect(mockHmacSHA256.mock.calls[i + 0][0]).toBe(secret);
		expect(mockHmacSHA256.mock.calls[i + 0][1]).toBe(a);
		expect(mockHmacSHA256.mock.calls[i + 1][0]).toBe(secret);
		expect(mockHmacSHA256.mock.calls[i + 1][1][0]).toBe(mockHmacSHA256.mock.results[i + 0].value);
		expect(mockHmacSHA256.mock.calls[i + 1][1][1]).toBe(seed);
	}
	expect(mockHmacSHA256.mock.calls.length).toBe(4);
	expect(rnd).toEqual(Buffer.concat([
		mockHmacSHA256.mock.results[1].value,
		mockHmacSHA256.mock.results[3].value
	]));
});

test('Get half block', () => {
	const p = new PrfSHA256('secret', 'seed');
	const rnd = p.fetch(16);
	expect(rnd).toEqual(mockHmacSHA256.mock.results[1].value.slice(0, 16));
});
