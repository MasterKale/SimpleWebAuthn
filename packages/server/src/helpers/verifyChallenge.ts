import { verify } from 'jsonwebtoken';
import { SignChallengePayload } from './signChallenge';

export default function verifyChallenge(
  signedChallenge: string,
  serverSecret: string,
): SignChallengePayload {
  return verify(signedChallenge, serverSecret) as SignChallengePayload;
}
