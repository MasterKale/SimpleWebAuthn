import { assertEquals } from '@std/assert';

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

Deno.test('should convert base64url-encoded clientDataJSON with crossOrigin and topOrigin to JSON', () => {
  assertEquals(
    decodeClientDataJSON(
      'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiY2hhbGxlbmdlIiwib3JpZ2luIjoiaHR0cHM6Ly9vcmlnaW4uY29tIiwiY3Jvc3NPcmlnaW4iOnRydWUsInRvcE9yaWdpbiI6Imh0dHBzOi8vdG9wLm9yaWdpbi5jb20ifQ',
    ),
    {
      type: 'webauthn.get',
      challenge: 'challenge',
      origin: 'https://origin.com',
      crossOrigin: true,
      topOrigin: 'https://top.origin.com',
    },
  );
});
