module.exports.Hmac = jest.fn();
module.exports.Hmac.prototype.update = jest.fn();
module.exports.Hmac.prototype.digest = jest.fn(() => Buffer.alloc(32));
module.exports.createHmac = jest.fn(() => new module.exports.Hmac());
