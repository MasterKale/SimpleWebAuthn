import { sign, verify } from 'jsonwebtoken';
import BaseAdapter, { assertIO, verifyAssertIO } from './BaseAdapter';

interface JWTChallengeAdapterConstructorOptions {
  secret: string;
  jwtExpiration?: string;
  rpID?: string;
  origin: string;
}

export interface SignChallengePayload {
  challenge: string;
  rpID: string;
  origin: string;
}

export default class JWTChallengeAdapter extends BaseAdapter {
  secret: string;
  recommendedSecretLength = 64;
  jwtExpiration = '2m';
  key = 'JWTChallengeAdapter';
  options: JWTChallengeAdapterConstructorOptions;

  constructor(options: JWTChallengeAdapterConstructorOptions) {
    super();
    const { secret, jwtExpiration } = options;
    this.options = options;
    if (secret && secret.length < this.recommendedSecretLength) {
      throw new Error(
        `jwt secret seems too weak please use a secret with more than ${this.recommendedSecretLength} chars`,
      );
    }
    this.secret = secret;
    if (jwtExpiration) this.jwtExpiration = jwtExpiration;
  }

  assert(opts: assertIO): assertIO {
    const rpID = opts.rpId || this.options.rpID;
    if (!rpID) throw new Error('You need to at least provide rpID on adapter');
    const origin = this.options.origin;

    if (!opts.adapters) opts.adapters = {};

    opts.adapters[this.key] = sign(
      { challenge: opts.challenge, rpID, origin } as SignChallengePayload,
      this.secret,
      { expiresIn: this.jwtExpiration },
    );

    return opts;
  }

  verifyAssert(opts: verifyAssertIO): verifyAssertIO {
    const response = opts.credential.adapters?.[this.key];
    if (!response) super.throwMissingKey();

    const signedChallengePayload = verify(response, this.secret) as SignChallengePayload;
    opts.expectedChallenge = signedChallengePayload.challenge;
    opts.expectedOrigin = signedChallengePayload.origin;
    opts.expectedRPID = signedChallengePayload.rpID;
    return opts;
  }
}
