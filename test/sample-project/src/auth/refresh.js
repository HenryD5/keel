const { sign } = require('jsonwebtoken');

function refresh(userId) {
  return sign({ sub: userId, kind: 'refresh' }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

module.exports = { refresh };
