import { assertEquals, assertRejects } from '@std/assert';

import { verifyRegistrationResponse } from '../verifyRegistrationResponse.ts';

Deno.test('should verify (broken) Packed response from Chrome virtual authenticator', async () => {
  /**
   * Chrome 89's WebAuthn dev tool enables developers to use "virtual" software authenticators in place
   * of typical authenticator hardware. Unfortunately a bug in these authenticators has leaf certs
   * specify the byte sequence "\x30\x03\x01\x01\x00" for the cert's Basic Constraints extension.
   * As per DER encoding rules this value _should_ be "\x30\x00".
   *
   * This bug was fixed in https://chromium-review.googlesource.com/c/chromium/src/+/2797998/, and
   * virtual authenticators should stop returning faulty values like this one starting in Chrome 91.
   * This unit test will remain for now in case this issue comes up again.
   */
  const verification = await verifyRegistrationResponse({
    response: {
      id: '5Hwc78jGjXrzOS8Mke9KhFZEtX54iYD-UEBKgvMXM64',
      rawId: '5Hwc78jGjXrzOS8Mke9KhFZEtX54iYD-UEBKgvMXM64',
      response: {
        attestationObject:
          'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhANUrPJzUYX7JGbo4yN_qsQ_2c7xw6br2U1y_OxNcFd1cAiAo6f7LtQ67viVKxs7TLo9nj6nxgxqwEaOpzQhGtdXbqGN4NWOBWQHgMIIB3DCCAYCgAwIBAgIBATANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJVUzERMA8GA1UECgwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMB4XDTE3MDcxNDAyNDAwMFoXDTQxMDMyNjAzNDIzNFowYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI1hfmXJUI5kvMVnOsgqZ5naPBRGaCwljEY__99Y39L6Pmw3i1PXlcSk3_tBme3Xhi8jq68CA7S4kRugVpmU4QGjKDAmMBMGCysGAQQBguUcAgEBBAQDAgUgMA8GA1UdEwEB_wQFMAMBAQAwDQYJKoZIhvcNAQELBQADRwAwRAIgK8W82BY7-iHUcd5mSfWX4R-uGdOk49XKTkV3L6ilUPQCIEs68ZEr_yAjG39UwNexAVLBfbxkDdkLZlMtBvUsV27PaGF1dGhEYXRhWKQ93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEUAAAABAQIDBAUGBwgBAgMEBQYHCAAg5Hwc78jGjXrzOS8Mke9KhFZEtX54iYD-UEBKgvMXM66lAQIDJiABIVgghBdEOBTvUm-jPaYY0wvvO_HzCupmyS7YQzagxtn1T5IiWCDwJ5XQ_SzKoiV64TXfdsTrnxFoNljUCzJOJhwrDyhkRA',
        clientDataJSON:
          'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiOUdJczBRUUJuYTE2eWN3NHN0U25BcWgyQWI2QWlIN1NTMF9YbTR5SjF6ayIsIm9yaWdpbiI6Imh0dHBzOi8vZGV2LmRvbnRuZWVkYS5wdyIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
        transports: ['usb'],
      },
      type: 'public-key',
      clientExtensionResults: {},
    },
    expectedChallenge: '9GIs0QQBna16ycw4stSnAqh2Ab6AiH7SS0_Xm4yJ1zk',
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  assertEquals(verification.verified, true);
});

Deno.test(
  'should succeed if id-fido-gen-ce-aaguid extension is present and matches AAGUID in auth data',
  async () => {
    const verification = await verifyRegistrationResponse({
      response: {
        'id':
          'U2FsdGVkX1_vZHKBBUOJpF_B3EuMclEyX-uqywz7QgHmOoaWkoaqm7GRIuc0HGBouOzOb1rov6NnpdP5_NXD8k_6HiEOCNpB5RMw9ZwXGtEPo9sVz9f2M8mV4dJZAa6n',
        'rawId':
          'U2FsdGVkX1_vZHKBBUOJpF_B3EuMclEyX-uqywz7QgHmOoaWkoaqm7GRIuc0HGBouOzOb1rov6NnpdP5_NXD8k_6HiEOCNpB5RMw9ZwXGtEPo9sVz9f2M8mV4dJZAa6n',
        'response': {
          'clientDataJSON':
            'eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY2hhbGxlbmdlIjoiamszcjFfNUFMZHk3ZDhGOFBEd0FOekt6LW5EN245bDVwN2dnZks1YWEzSXZDaVpHbWt2S29ZR3UtZnJ4bGRZYUZQNC1UbkxRNGRoQWpreldyZE5ieVEiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0',
          'attestationObject':
            'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjeDVjgVkB_zCCAfswggGgoAMCAQICEFw-WA37iCeJVBiKwlH-bfwwCgYIKoZIzj0EAwIwLjELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA0lCTTERMA8GA1UEAwwIRklET1RFU1QwIhgPMjAyNDA5MTIxNjE3MTRaGA8yMDUyMDEyODE3MTcxNFowVzELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA0lCTTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEWMBQGA1UEAwwNUEFDS0VELVNJR05FUjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL83SCKq9bAqrbi1sTTV9HxlseMD2MbHYXHGROZGx0CFpHPayDeYqo6dWo4_6-z8_RUHwMvbNIUaxgAC5e3PacejczBxMB0GA1UdDgQWBBRNL7NrNzBPnl6RAyWY9tCL8xBtzDAfBgNVHSMEGDAWgBQX_QoP8NpeXBvZlnioDn4WYG-t8zAMBgNVHRMBAf8EAjAAMCEGCysGAQQBguUcAQEEBBIEEP_Z9JTrc0hEvWhmk4FVf_cwCgYIKoZIzj0EAwIDSQAwRgIhAMN6MkZp5DvxlqtRTIVsok0zxbsW76roUUprQ0lEATbxAiEAmrp7VhF_0RP-CJI9cCwKGKs9jhEVVZmZ5dWpOp6hNnhjc2lnWEcwRQIhAJSxn_AUAyoBZQhlN_PW-R5FsnDJCwZ__vFIZqdI5p6JAiBenN17iGqijwNh_wB-Ka_yUqPMLlIrE4DFW4E6JFXSQGhhdXRoRGF0YVjkdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAAAP_Z9JTrc0hEvWhmk4FVf_cAYFNhbHRlZF9f72RygQVDiaRfwdxLjHJRMl_rqssM-0IB5jqGlpKGqpuxkSLnNBxgaLjszm9a6L-jZ6XT-fzVw_JP-h4hDgjaQeUTMPWcFxrRD6PbFc_X9jPJleHSWQGup6UBAgMmIAEhWCAaFLI3Hlb0boERsvlz69qracfxATqaHb6YTkBaVRofXSJYIJe4sLH76hnJInTxVcz5ZA6tfnvBqFWxPTp10H9KkG0_',
          'publicKeyAlgorithm': -7,
          'publicKey':
            'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGhSyNx5W9G6BEbL5c-vaq2nH8QE6mh2-mE5AWlUaH12XuLCx--oZySJ08VXM-WQOrX57wahVsT06ddB_SpBtPw',
          'authenticatorData':
            'dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAAAP_Z9JTrc0hEvWhmk4FVf_cAYFNhbHRlZF9f72RygQVDiaRfwdxLjHJRMl_rqssM-0IB5jqGlpKGqpuxkSLnNBxgaLjszm9a6L-jZ6XT-fzVw_JP-h4hDgjaQeUTMPWcFxrRD6PbFc_X9jPJleHSWQGup6UBAgMmIAEhWCAaFLI3Hlb0boERsvlz69qracfxATqaHb6YTkBaVRofXSJYIJe4sLH76hnJInTxVcz5ZA6tfnvBqFWxPTp10H9KkG0_',
          'transports': ['internal'],
        },
        'type': 'public-key',
        'clientExtensionResults': {},
      },
      expectedChallenge:
        'jk3r1_5ALdy7d8F8PDwANzKz-nD7n9l5p7ggfK5aa3IvCiZGmkvKoYGu-frxldYaFP4-TnLQ4dhAjkzWrdNbyQ',
      expectedOrigin: 'https://webauthn.io',
      expectedRPID: 'webauthn.io',
    });

    assertEquals(verification.verified, true);
  },
);

Deno.test(
  'should fail if id-fido-gen-ce-aaguid extension is present and does not match AAGUID in auth data',
  async () => {
    // const response = await ;
    await assertRejects(
      () =>
        verifyRegistrationResponse({
          response: {
            'id':
              'U2FsdGVkX1_TltrAMvHmwb2E0eCxQwxNxipf9knba5awjus9BXmWXMKFPsDdHF0oILE1KYanoajKcWXD9KVw4dwX-aEyr2CpA-7kKAUchMmuLWSXAxspPHRy58a91BDP',
            'rawId':
              'U2FsdGVkX1_TltrAMvHmwb2E0eCxQwxNxipf9knba5awjus9BXmWXMKFPsDdHF0oILE1KYanoajKcWXD9KVw4dwX-aEyr2CpA-7kKAUchMmuLWSXAxspPHRy58a91BDP',
            'response': {
              'clientDataJSON':
                'eyJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY2hhbGxlbmdlIjoicHhPRFZXTzgxUUVvaW40djExLW1ZR05pY2IyWG81NUFBbFJINFhxazIzUW50SkU5ZTlhQkR0YVQ5QzV6UWk1UTdyZUNVMzduMGQ0a255NTZSc0ZtYnciLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0',
              'attestationObject':
                'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjeDVjgVkB_zCCAfswggGgoAMCAQICEFw-WA37iCeJVBiKwlH-bfwwCgYIKoZIzj0EAwIwLjELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA0lCTTERMA8GA1UEAwwIRklET1RFU1QwIhgPMjAyNDA5MTIxNjE3MTRaGA8yMDUyMDEyODE3MTcxNFowVzELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA0lCTTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEWMBQGA1UEAwwNUEFDS0VELVNJR05FUjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL83SCKq9bAqrbi1sTTV9HxlseMD2MbHYXHGROZGx0CFpHPayDeYqo6dWo4_6-z8_RUHwMvbNIUaxgAC5e3PacejczBxMB0GA1UdDgQWBBRNL7NrNzBPnl6RAyWY9tCL8xBtzDAfBgNVHSMEGDAWgBQX_QoP8NpeXBvZlnioDn4WYG-t8zAMBgNVHRMBAf8EAjAAMCEGCysGAQQBguUcAQEEBBIEEP_Z9JTrc0hEvWhmk4FVf_cwCgYIKoZIzj0EAwIDSQAwRgIhAMN6MkZp5DvxlqtRTIVsok0zxbsW76roUUprQ0lEATbxAiEAmrp7VhF_0RP-CJI9cCwKGKs9jhEVVZmZ5dWpOp6hNnhjc2lnWEYwRAIgCBrwbKfvHiiWHQ2ATt9fJcGVJZGynmm5f77cFRwiU_8CIGg8NgtGtPrx6giI3UMsWByNtAM1UN9vx1EKu90AEc5eaGF1dGhEYXRhWOR0puqSE8mcL3SyJJKzIM9AJiqUwalQoDl_KSULYIQe8EUAAAAAM3vvU7aPQEWMt8r6dI_8DgBgU2FsdGVkX1_TltrAMvHmwb2E0eCxQwxNxipf9knba5awjus9BXmWXMKFPsDdHF0oILE1KYanoajKcWXD9KVw4dwX-aEyr2CpA-7kKAUchMmuLWSXAxspPHRy58a91BDPpQECAyYgASFYIFVEnAtmwsWP0FKQxGwJa2yGzmA8koGNYoJclMQzlsDJIlggwZRIX1gdfh2q_GBdHZgAy5vO7hsL338yuxPevvZgSp8',
              'publicKeyAlgorithm': -7,
              'publicKey':
                'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVUScC2bCxY_QUpDEbAlrbIbOYDySgY1iglyUxDOWwMnBlEhfWB1-Har8YF0dmADLm87uGwvffzK7E96-9mBKnw',
              'authenticatorData':
                'dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAAADN771O2j0BFjLfK-nSP_A4AYFNhbHRlZF9f05bawDLx5sG9hNHgsUMMTcYqX_ZJ22uWsI7rPQV5llzChT7A3RxdKCCxNSmGp6GoynFlw_SlcOHcF_mhMq9gqQPu5CgFHITJri1klwMbKTx0cufGvdQQz6UBAgMmIAEhWCBVRJwLZsLFj9BSkMRsCWtshs5gPJKBjWKCXJTEM5bAySJYIMGUSF9YHX4dqvxgXR2YAMubzu4bC99_MrsT3r72YEqf',
              'transports': ['internal'],
            },
            'type': 'public-key',
            'clientExtensionResults': {},
          },
          expectedChallenge:
            'pxODVWO81QEoin4v11-mYGNicb2Xo55AAlRH4Xqk23QntJE9e9aBDtaT9C5zQi5Q7reCU37n0d4kny56RsFmbw',
          expectedOrigin: 'https://webauthn.io',
          expectedRPID: 'webauthn.io',
        }),
      Error,
      '1.3.6.1.4.1.45724.1.1.4',
    );
  },
);
