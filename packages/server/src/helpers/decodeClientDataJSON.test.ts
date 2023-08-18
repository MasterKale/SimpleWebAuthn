import { assertEquals } from 'https://deno.land/std@0.198.0/assert/mod.ts';

import { decodeClientDataJSON } from './decodeClientDataJSON.ts';

Deno.test('should convert base64url-encoded attestation clientDataJSON to JSON', () => {
  assertEquals(
    decodeClientDataJSON(
      'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWko0YW12QnpOUGVMb3lLVE04bDlqamFmMDhXc0V0TG5OSENGZnhacGEybjlfU21NUnR5VjZlYlNPSUFfUGNsOHBaUjl5Y1ZhaW5SdV9rUDhRaTZiemciLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIn0',
    ),
    {
      type: 'webauthn.create',
      challenge:
        'ZJ4amvBzNPeLoyKTM8l9jjaf08WsEtLnNHCFfxZpa2n9_SmMRtyV6ebSOIA_Pcl8pZR9ycVainRu_kP8Qi6bzg',
      origin: 'https://webauthn.io',
    },
  );
});
