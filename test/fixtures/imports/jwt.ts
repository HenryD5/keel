import jwt from 'jsonwebtoken';

const decoded = jwt.verify(token, secret);
const signed = jwt.sign(decoded, secret);
// jwt.decode(token) y jsonwebtoken no cuentan
const similar = 'jsonwebtoken-extra';
