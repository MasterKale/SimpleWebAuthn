import verifyAttestationResponse from './verifyAttestationResponse';

jest.spyOn(console, 'log').mockImplementation();
jest.spyOn(console, 'debug').mockImplementation();

test('should verify FIDO U2F attestation', () => {
  const verification = verifyAttestationResponse(
    {
      base64AttestationObject: 'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhAK40WxA0t7py7AjEXvwGw' +
        'TlmqlvrOks5g9lf+9zXzRiVAiEA3bv60xyXveKDOusYzniD7CDSostCet9PYK7FLdnTdZNjeDVjgVkCwTCCAr0wg' +
        'gGloAMCAQICBCrnYmMwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhb' +
        'CA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG4xCzAJBgNVBAYTAlNFMRIwEAYDV' +
        'QQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xJzAlBgNVBAMMHll1Ymljb' +
        'yBVMkYgRUUgU2VyaWFsIDcxOTgwNzA3NTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCoDhl5gQ9meEf8QqiVUV' +
        '4S/Ca+Oax47MhcpIW9VEhqM2RDTmd3HaL3+SnvH49q8YubSRp/1Z1uP+okMynSGnj+jbDBqMCIGCSsGAQQBgsQKA' +
        'gQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgQwMCEGCysGAQQBguUcAQEEBBIEEG1Eu' +
        'pv27C5JuTAMj+kgy3MwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAclfQPNzD4RVphJDW+A75W1MHI' +
        '3PZ5kcyYysR3Nx3iuxr1ZJtB+F7nFQweI3jL05HtFh2/4xVIgKb6Th4eVcjMecncBaCinEbOcdP1sEli9Hk2eVm1' +
        'XB5A0faUjXAPw/+QLFCjgXG6ReZ5HVUcWkB7riLsFeJNYitiKrTDXFPLy+sNtVNutcQnFsCerDKuM81TvEAigkIb' +
        'KCGlq8M/NvBg5j83wIxbCYiyV7mIr3RwApHieShzLdJo1S6XydgQjC+/64G5r8C+8AVvNFR3zXXCpio5C3KRIj88' +
        'HEEIYjf6h1fdLfqeIsq+cUUqbq5T+c4nNoZUZCysTB9v5EY4akp+GhhdXRoRGF0YVjEAbElFazplpnc037DORGDZ' +
        'NjDq86cN9vm6+APoAM20wtBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQGFYevaR71ptU5YtXOSnVzPQTsGgK+gLiBKnq' +
        'PWBmZXNRvjISqlLxiwApzlrfkTc3lEMYMatjeACCnsijOkNEGOlAQIDJiABIVggdWLG6UvGyHFw/k/bv6/k6z/LL' +
        'gSO5KXzXw2EcUxkEX8iWCBeaVLz/cbyoKvRIg/q+q7tan0VN+i3WR0BOBCcuNP7yw==',
      base64ClientDataJSON: 'eyJjaGFsbGVuZ2UiOiJVMmQ0TjNZME0wOU1jbGRQYjFSNVpFeG5UbG95IiwiY2xpZW50' +
        'RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly9jbG92ZXIu' +
        'bWlsbGVydGltZS5kZXY6MzAwMCIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ==',
    },
    'https://clover.millertime.dev:3000',
  );

  expect(verification.verified).toEqual(true);
  expect(verification.authenticatorInfo?.fmt).toEqual('fido-u2f');
  expect(verification.authenticatorInfo?.counter).toEqual(0);
  expect(verification.authenticatorInfo?.base64PublicKey).toEqual(
    'BHVixulLxshxcP5P27-v5Os_yy4EjuSl818NhHFMZBF_XmlS8_3G8qCr0SIP6vqu7Wp9FTfot1kdATgQnLjT-8s',
  );
  expect(verification.authenticatorInfo?.base64CredentialID).toEqual(
    'YVh69pHvWm1Tli1c5KdXM9BOwaAr6AuIEqeo9YGZlc1G-MhKqUvGLACnOWt-RNzeUQxgxq2N4AIKeyKM6Q0QYw',
  );
});

test('should verify Packed attestation', () => {
  const verification = verifyAttestationResponse(
    {
      base64AttestationObject: 'o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIhANvrPZMUFrl_rvlgR' +
        'qz6lCPlF6B4y885FYUCCrhrzAYXAiAb4dQKXbP3IimsTTadkwXQlrRVdxzlbmPXt847-Oh6r2hhdXRoRGF0YVjhP' +
        'dxHEOnAiLIp26idVjIguzn3Ipr_RlsKZWsa-5qK-KBFXsOO-a3OAAI1vMYKZIsLJfHwVQMAXQGE4WNXLCDWOCa2x' +
        '8hpqk5dZy_xdc4wBd4UgCJ4M_JAHI7oJgDDVb8WUcKqRB_mzRxwCL9vdTl-ZKPXg3_-Zrt1Adgb7EnK9ivqaTOKM' +
        'DqRrKsIObWYJaqpsSJtUKUBAgMmIAEhWCBKMVVaivqCBpqqAxMjuCo5jMeUdh3jDOC0EF4fLBNNTyJYILc7rqDDe' +
        'X1pwCLrl3ZX7IThrtZNwKQVLQyfHiorqP-n',
      base64ClientDataJSON: 'eyJjaGFsbGVuZ2UiOiJjelpRU1dKQ2JsQlFibkpIVGxOQ2VFNWtkRVJ5VkRkVmNsWlpT' +
        'a3M1U0UwIiwib3JpZ2luIjoiaHR0cHM6Ly9kZXYuZG9udG5lZWRhLnB3IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0' +
        'ZSJ9',
    },
    'https://dev.dontneeda.pw'
  )

  expect(verification.verified).toEqual(true);
  expect(verification.authenticatorInfo?.fmt).toEqual('packed');
  expect(verification.authenticatorInfo?.counter).toEqual(1589874425);
  expect(verification.authenticatorInfo?.base64PublicKey).toEqual(
    'BEoxVVqK-oIGmqoDEyO4KjmMx5R2HeMM4LQQXh8sE01PtzuuoMN5fWnAIuuXdlfshOGu1k3ApBUtDJ8eKiuo_6c',
  );
  expect(verification.authenticatorInfo?.base64CredentialID).toEqual(
    'AYThY1csINY4JrbHyGmqTl1nL_F1zjAF3hSAIngz8kAcjugmAMNVvxZRwqpEH-bNHHAIv291OX5ko9eDf_5mu3U' +
    'B2BvsScr2K-ppM4owOpGsqwg5tZglqqmxIm1Q',
  );
});

