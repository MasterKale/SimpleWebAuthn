import verifyAttestationResponse from '../verifyAttestationResponse';

test('should verify Packed response from Chrome virtual authenticator', async () => {
  /**
   * This unit test will ensure future compatibility with Chrome virtual authenticators.
   *
   * Context:
   *
   * Chrome's WebAuthn dev tool enables developers to use "virtual" software authenticators in place
   * of typical authenticator hardware. The reason this test exists is to ensure SimpleWebAuthn can
   * handle leaf certs, such as the ones in these virtual authenticators, that specify the byte
   * sequence "\x30\x03\x01\x01\x00" for the cert's Basic Constraints extension.
   *
   * As of March 2021 the jsrsasign@^10.0.5 library has a hardcoded check for "30030101ff", but
   * not "3003010100" (notice the difference between "ff" and "00"), indicating whether or not this
   * is a certificate authority certificate:
   *
   * https://github.com/kjur/jsrsasign/blob/482e651f2bb380dad3da4bbf0ae220fe3021d407/src/x509-1.1.js#L660
   *
   * Physical hardware authenticators have been observed to specify "3000" for this constraint;
   * this value evaluates to `!!undefined` => `false`, satisfying the Packed attestation
   * verification's requirement that, "the Basic Constraints extension MUST have the CA component
   * set to false.""
   *
   * https://w3c.github.io/webauthn/#sctn-packed-attestation-cert-requirements
   *
   * SimpleWebAuthn will have to implement its own workaround until this issue is resolved in
   * jsrsasign.
   */
  const verification = await verifyAttestationResponse({
    credential: {
      id: '5Hwc78jGjXrzOS8Mke9KhFZEtX54iYD-UEBKgvMXM64',
      rawId: '5Hwc78jGjXrzOS8Mke9KhFZEtX54iYD-UEBKgvMXM64',
      response: {
        attestationObject:
          'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhANUrPJzUYX7JGbo4yN_qsQ_2c7xw6br2U1y_OxNcFd1cAiAo6f7LtQ67viVKxs7TLo9nj6nxgxqwEaOpzQhGtdXbqGN4NWOBWQHgMIIB3DCCAYCgAwIBAgIBATANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJVUzERMA8GA1UECgwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMB4XDTE3MDcxNDAyNDAwMFoXDTQxMDMyNjAzNDIzNFowYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI1hfmXJUI5kvMVnOsgqZ5naPBRGaCwljEY__99Y39L6Pmw3i1PXlcSk3_tBme3Xhi8jq68CA7S4kRugVpmU4QGjKDAmMBMGCysGAQQBguUcAgEBBAQDAgUgMA8GA1UdEwEB_wQFMAMBAQAwDQYJKoZIhvcNAQELBQADRwAwRAIgK8W82BY7-iHUcd5mSfWX4R-uGdOk49XKTkV3L6ilUPQCIEs68ZEr_yAjG39UwNexAVLBfbxkDdkLZlMtBvUsV27PaGF1dGhEYXRhWKQ93EcQ6cCIsinbqJ1WMiC7Ofcimv9GWwplaxr7mor4oEUAAAABAQIDBAUGBwgBAgMEBQYHCAAg5Hwc78jGjXrzOS8Mke9KhFZEtX54iYD-UEBKgvMXM66lAQIDJiABIVgghBdEOBTvUm-jPaYY0wvvO_HzCupmyS7YQzagxtn1T5IiWCDwJ5XQ_SzKoiV64TXfdsTrnxFoNljUCzJOJhwrDyhkRA',
        clientDataJSON:
          'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiOUdJczBRUUJuYTE2eWN3NHN0U25BcWgyQWI2QWlIN1NTMF9YbTR5SjF6ayIsIm9yaWdpbiI6Imh0dHBzOi8vZGV2LmRvbnRuZWVkYS5wdyIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
      },
      type: 'public-key',
      clientExtensionResults: {},
      transports: ['usb'],
    },
    expectedChallenge: '9GIs0QQBna16ycw4stSnAqh2Ab6AiH7SS0_Xm4yJ1zk',
    expectedOrigin: 'https://dev.dontneeda.pw',
    expectedRPID: 'dev.dontneeda.pw',
  });

  expect(verification.verified).toEqual(true);
});
