// Strict base64url: no padding, and only the one encoding that the bytes have (Go's RawURLEncoding.Strict).
export function decodeBase64Url(value: string): Buffer | undefined {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) return undefined;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.toString('base64url') === value ? bytes : undefined;
}
