import base64url from 'base64url';

/**
 * Process a JWT into Javascript-friendly data structures
 */
export default function parseJWT<T1, T2>(jwt: string): [T1, T2, string] {
  const parts = jwt.split('.');
  return [
    JSON.parse(base64url.decode(parts[0])) as T1,
    JSON.parse(base64url.decode(parts[1])) as T2,
    parts[2],
  ];
}
