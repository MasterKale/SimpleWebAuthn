import signChallenge from './signChallenge';
import verifyChallenge from './verifyChallenge';

test('should sign challenge', () => {
  const serverSecret = '17hMcXI0AvkM7f4OWxBPwRE30D6HnoFBHAJT8Wt6AnbOh0Y9X2sXERpXaavEVEDH';
  const payload = { challenge: 'test', rpID: 'test', origin: 'test' };
  try {
    signChallenge(payload, 'test');
    fail();
  } catch (e) {
    expect(e.message).toContain(
      'serverSecret seems too weak please use a secret with more than 64 chars',
    );
  }

  expect(signChallenge(payload)).toEqual(undefined);

  const verifiedChallenge = verifyChallenge(
    signChallenge(payload, serverSecret) as string,
    serverSecret,
  );

  expect(verifiedChallenge.challenge).toEqual('test');
  expect(verifiedChallenge.rpID).toEqual('test');
  expect(verifiedChallenge.origin).toEqual('test');
});
