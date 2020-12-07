import { sign, verify, VerifyOptions, SignOptions } from 'jsonwebtoken';
import BaseAdapter, { assertIO, verifyAssertIO, attestIO, verifyAttestIO } from './BaseAdapter';

interface JwtOptions {
  verify: VerifyOptions;
  sign: SignOptions;
}
interface JWTChallengeAdapterConstructorOptions {
  secretOrPrivateKey: string;
  jwtOptions?: JwtOptions;
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
  key = 'JWTChallengeAdapter';
  jwtOptions: JwtOptions = {
    verify: { algorithms: ['HS256'] },
    sign: { algorithm: 'HS256', expiresIn: '2m' },
  };
  options: JWTChallengeAdapterConstructorOptions;

  constructor(options: JWTChallengeAdapterConstructorOptions) {
    super();
    const { secretOrPrivateKey, jwtOptions } = options;
    this.options = options;
    if (secretOrPrivateKey && secretOrPrivateKey.length < this.recommendedSecretLength) {
      throw new Error(
        `jwt secret seems too weak please use a secret with more than ${this.recommendedSecretLength} chars`,
      );
    }
    this.secret = secretOrPrivateKey;
    if (jwtOptions) this.jwtOptions = jwtOptions;
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
      { expiresIn: '2m', ...this.jwtOptions.sign },
    );
  }

  verifyChallenge(opts: verifyAssertIO | verifyAttestIO): void {
    const response = opts.credential.adapters?.[this.key];
    if (!response) super.throwMissingKey();

    const signedChallengePayload = verify(
      response,
      this.secret,
      this.jwtOptions.verify,
    ) as SignChallengePayload;
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
