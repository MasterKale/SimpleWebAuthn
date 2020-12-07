import {
  PublicKeyCredentialRequestOptionsJSON,
  PublicKeyCredentialCreationOptionsJSON,
} from '@simplewebauthn/typescript-types';

import { VerifyAssertionOptions } from '../assertion/options';
import { VerifyAttestationOptions } from '../attestation/options';

export {
  PublicKeyCredentialRequestOptionsJSON as assertIO,
  PublicKeyCredentialCreationOptionsJSON as attestIO,
} from '@simplewebauthn/typescript-types';

export { VerifyAssertionOptions as verifyAssertIO } from '../assertion/options';
export { VerifyAttestationOptions as verifyAttestIO } from '../attestation/options';

export default class BaseAdapter {
  key = 'BaseAdapter';

  assert(response: PublicKeyCredentialRequestOptionsJSON): PublicKeyCredentialRequestOptionsJSON {
    return response;
  }

  throwMissingKey(): void {
    throw new Error(`Missing ${this.key} key into adapters`);
  }

  verifyAssert(request: VerifyAssertionOptions): VerifyAssertionOptions {
    return request;
  }

  attest(response: PublicKeyCredentialCreationOptionsJSON): PublicKeyCredentialCreationOptionsJSON {
    return response;
  }

  verifyAttest(request: VerifyAttestationOptions): VerifyAttestationOptions {
    return request;
  }
}
