import { sign } from 'jsonwebtoken';

const recommendedServerSecretLength = 64;

export interface SignChallengePayload {
  challenge: string;
  rpID: string;
  origin: string;
}

export default function signChallenge(
  payload: SignChallengePayload,
  serverSecret?: string,
): string | undefined {
  if (!serverSecret) return undefined;

  if (serverSecret && serverSecret.length < recommendedServerSecretLength) {
    throw new Error(
      `serverSecret seems too weak please use a secret with more than ${recommendedServerSecretLength} chars`,
    );
  }

  return sign(payload, serverSecret, { expiresIn: '5m' });
}
