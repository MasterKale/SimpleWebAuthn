import verifyAssertionResponse from './verifyAssertionResponse';

test('', () => {
  const verification = verifyAssertionResponse(
    {
      base64AuthenticatorData: 'PdxHEOnAiLIp26idVjIguzn3Ipr_RlsKZWsa-5qK-KABAAAAhw',
      base64ClientDataJSON: 'eyJjaGFsbGVuZ2UiOiJXRzVRU21RM1oyOTROR2gyTVROUk56WnViVmhMTlZZMWMwOHRP' +
        'V3BLVG5JIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoi' +
        'aHR0cHM6Ly9kZXYuZG9udG5lZWRhLnB3IiwidHlwZSI6IndlYmF1dGhuLmdldCJ9',
      base64Signature: 'MEQCIHZYFY3LsKzI0T9XRwEACl7YsYZysZ2HUw3q9f7tlq3wAiBNbyBbQMNM56P6Z00tBEZ6v' +
        'II4f9Al-p4pZw7OBpSaog',
      userHandle: null,
    },
    'https://dev.dontneeda.pw',
    {
      base64PublicKey: 'BBMQEnZRfg4ASys9kfGUj99Xlsa028wqYJZw8xuGahPQJWN3K9D9DajLxzKlY7uf_ulA5D6gh' +
        'UJ9hrouDX84S_I',
      base64CredentialID: 'wJZRtQbYjKlpiRnzet7yyVizdsj_oUhi11kFbKyO0hc5gIg-4xeaTC9YC9y9sfow6gO3jE' +
        'MoONBKNX4SmSclmQ',
      counter: 134,
    },
  );

  expect(verification.verified).toEqual(true);
});
