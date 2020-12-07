import { sign, verify } from 'jsonwebtoken';
import BaseAdapter, { assertIO, verifyAssertIO, attestIO, verifyAttestIO } from './BaseAdapter';

type JwtAlgorithms = 'HS256' | 'RS256' | 'HS512' | 'RS512';
interface JWTChallengeAdapterConstructorOptions {
  secretOrPrivateKey: string;
  jwtAlgorithm?: JwtAlgorithms;
  jwtExpiration?: string;
  rpID: string;
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
  jwtAlgorithm: JwtAlgorithms = 'HS256';

  constructor(options: JWTChallengeAdapterConstructorOptions) {
    super();
    const { secretOrPrivateKey, jwtExpiration, jwtAlgorithm } = options;
    this.options = options;
    if (secretOrPrivateKey && secretOrPrivateKey.length < this.recommendedSecretLength) {
      throw new Error(
        `jwt secret seems too weak please use a secret with more than ${this.recommendedSecretLength} chars`,
      );
    }
    this.secret = secretOrPrivateKey;
    if (jwtExpiration) this.jwtExpiration = jwtExpiration;
    if (jwtAlgorithm) this.jwtAlgorithm = jwtAlgorithm;
  }

  assert(opts: assertIO): assertIO {
    this.signChallenge(opts);
    return opts;
  }

  signChallenge(opts: assertIO | attestIO): void {
    if (!opts.adapters) opts.adapters = {};

    opts.adapters[this.key] = sign(
      {
        challenge: opts.challenge,
        rpID: this.options.rpID,
        origin: this.options.origin,
      } as SignChallengePayload,
      this.secret,
      { expiresIn: this.jwtExpiration, algorithm: this.jwtAlgorithm },
    );
  }

  verifyChallenge(opts: verifyAssertIO | verifyAttestIO): void {
    const response = opts.credential.adapters?.[this.key];
    if (!response) super.throwMissingKey();

    const signedChallengePayload = verify(response, this.secret, {
      algorithms: [this.jwtAlgorithm],
    }) as SignChallengePayload;
    opts.expectedChallenge = signedChallengePayload.challenge;
    opts.expectedOrigin = signedChallengePayload.origin;
    opts.expectedRPID = signedChallengePayload.rpID;
  }

  verifyAssert(opts: verifyAssertIO): verifyAssertIO {
    this.verifyChallenge(opts);
    return opts;
  }

  attest(opts: attestIO): attestIO {
    this.signChallenge(opts);
    return opts;
  }

  verifyAttest(opts: verifyAttestIO): verifyAttestIO {
    this.verifyChallenge(opts);
    return opts;
  }
}
