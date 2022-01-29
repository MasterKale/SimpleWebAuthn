/**
 * Make sure "now" is within a specific time frame
 */
export function validateCertificateValidityWindow(notBefore: Date, notAfter: Date): boolean {
  const now = new Date();
  return notBefore < now && now < notAfter;
}
