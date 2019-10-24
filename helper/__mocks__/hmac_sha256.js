let i = 0;
module.exports = jest.fn(() => Buffer.alloc(32, i++));
