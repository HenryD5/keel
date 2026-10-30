const { sign: firmar } = require('jsonwebtoken');

module.exports = firmar(payload, secret);
