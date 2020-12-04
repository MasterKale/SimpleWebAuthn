import { verify } from 'jsonwebtoken';
import signChallenge from './signChallenge';

test('should sign challenge', () => {
  const serverSecret = '17hMcXI0AvkM7f4OWxBPwRE30D6HnoFBHAJT8Wt6AnbOh0Y9X2sXERpXaavEVEDH';
  try {
    signChallenge('test', 'test');
    fail();
  } catch (e) {
    expect(e).toContain('serverSecret seems too weak please use a secret with more than 64 chars');
  }

  expect(signChallenge('test')).toEqual(undefined);

  const verifiedChallenge = verify(signChallenge('test', serverSecret), serverSecret) as {
    challenge: string;
  };

  expect(verifiedChallenge.challenge).toEqual('test');
});
