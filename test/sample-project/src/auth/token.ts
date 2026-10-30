import jwt from 'jsonwebtoken';

const SECRET = process.env.JWT_SECRET ?? 'dev-secret';

export function issueToken(userId: string): string {
  return jwt.sign({ sub: userId }, SECRET, { expiresIn: '1h' });
}

export function readToken(token: string): unknown {
  return jwt.verify(token, SECRET);
}
