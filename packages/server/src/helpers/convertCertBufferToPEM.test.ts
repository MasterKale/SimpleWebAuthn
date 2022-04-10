import convertCertBufferToPEM from "./convertCertBufferToPEM";

test('should return pem when input is base64URLString', () => {
  const input = "Y2VydEJ1ZmZlclN0cmluZw";
  const actual = convertCertBufferToPEM(input);
  expect(actual).toEqual(`-----BEGIN CERTIFICATE-----\nY2VydEJ1ZmZlclN0cmluZw==\n-----END CERTIFICATE-----\n`)
});

test('should return pem when input is buffer', () => {
  const input = new Buffer(10);
  const actual = convertCertBufferToPEM(input);
  expect(actual).toEqual(`-----BEGIN CERTIFICATE-----\nAAAAAAAAAAAAAA==\n-----END CERTIFICATE-----\n`)
});
