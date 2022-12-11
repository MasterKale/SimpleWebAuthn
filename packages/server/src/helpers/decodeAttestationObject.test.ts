import { decodeAttestationObject } from './decodeAttestationObject';

test('should decode base64url-encoded indirect attestationObject', () => {
  const decoded = decodeAttestationObject(
    Buffer.from(
      'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEAbElFazplpnc037DORGDZNjDq86cN9vm6' +
        '+APoAM20wtBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQKmPuEwByQJ3e89TccUSrCGDkNWquhevjLLn/' +
        'KNZZaxQQ0steueoG2g12dvnUNbiso8kVJDyLa+6UiA34eniujWlAQIDJiABIVggiUk8wN2j' +
        '+3fkKI7KSiLBkKzs3FfhPZxHgHPnGLvOY/YiWCBv7+XyTqArnMVtQ947/8Xk8fnVCdLMRWJGM1VbNevVcQ==',
      'base64',
    ),
  );

  expect(decoded.get('fmt')).toEqual('none');
  expect(decoded.get('attStmt')).toEqual(new Map());
  expect(decoded.get('authData')).toBeDefined();
});

test('should decode base64url-encoded direct attestationObject', () => {
  const decoded = decodeAttestationObject(
    Buffer.from(
      'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhAK40WxA0t7py7AjEXvwGwTlmqlvrOk' +
        's5g9lf+9zXzRiVAiEA3bv60xyXveKDOusYzniD7CDSostCet9PYK7FLdnTdZNjeDVjgVkCwTCCAr0wggGloAMCAQICBCrn' +
        'YmMwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMT' +
        'QwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG4xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNV' +
        'BAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xJzAlBgNVBAMMHll1YmljbyBVMkYgRUUgU2VyaWFsIDcxOTgwNzA3NT' +
        'BZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCoDhl5gQ9meEf8QqiVUV4S/Ca+Oax47MhcpIW9VEhqM2RDTmd3HaL3+SnvH' +
        '49q8YubSRp/1Z1uP+okMynSGnj+jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBgu' +
        'UcAgEBBAQDAgQwMCEGCysGAQQBguUcAQEEBBIEEG1Eupv27C5JuTAMj+kgy3MwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0B' +
        'AQsFAAOCAQEAclfQPNzD4RVphJDW+A75W1MHI3PZ5kcyYysR3Nx3iuxr1ZJtB+F7nFQweI3jL05HtFh2/4xVIgKb6Th4eV' +
        'cjMecncBaCinEbOcdP1sEli9Hk2eVm1XB5A0faUjXAPw/+QLFCjgXG6ReZ5HVUcWkB7riLsFeJNYitiKrTDXFPLy+sNtVN' +
        'utcQnFsCerDKuM81TvEAigkIbKCGlq8M/NvBg5j83wIxbCYiyV7mIr3RwApHieShzLdJo1S6XydgQjC+/64G5r8C+8AVvN' +
        'FR3zXXCpio5C3KRIj88HEEIYjf6h1fdLfqeIsq+cUUqbq5T+c4nNoZUZCysTB9v5EY4akp+GhhdXRoRGF0YVjEAbElFazp' +
        'lpnc037DORGDZNjDq86cN9vm6+APoAM20wtBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQGFYevaR71ptU5YtXOSnVzPQTsGgK+' +
        'gLiBKnqPWBmZXNRvjISqlLxiwApzlrfkTc3lEMYMatjeACCnsijOkNEGOlAQIDJiABIVggdWLG6UvGyHFw/k/bv6/k6z/L' +
        'LgSO5KXzXw2EcUxkEX8iWCBeaVLz/cbyoKvRIg/q+q7tan0VN+i3WR0BOBCcuNP7yw==',
      'base64',
    ),
  );

  expect(decoded.get('fmt')).toEqual('fido-u2f');
  expect(decoded.get('attStmt').get('sig')).toBeDefined();
  expect(decoded.get('attStmt').get('x5c')).toBeDefined();
  expect(decoded.get('authData')).toBeDefined();
});
