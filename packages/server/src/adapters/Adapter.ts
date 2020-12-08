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

export default abstract class Adapter {
  key = 'Adapter';

  /**
   * Modify the output of the assertion request
   * @param assertResponse response from the assertion request
   */
  assert(
    assertResponse: PublicKeyCredentialRequestOptionsJSON,
  ): PublicKeyCredentialRequestOptionsJSON {
    return assertResponse;
  }

  throwMissingKey(): void {
    throw new Error(`Missing ${this.key} key into adapters`);
  }

  /**
   * Modify the input options of verify assertion before running the assertion verification
   * @param verifyAssertionOptions options of verify assertion
   */
  verifyAssert(verifyAssertionOptions: VerifyAssertionOptions): VerifyAssertionOptions {
    return verifyAssertionOptions;
  }

  /**
   * Modify the output of the attestation request
   * @param attestResponse response from the attestation request
   */
  attest(
    attestResponse: PublicKeyCredentialCreationOptionsJSON,
  ): PublicKeyCredentialCreationOptionsJSON {
    return attestResponse;
  }

  /**
   * Modify the input options of verify attestation before running the attestation verification
   * @param verifyAttestationOptions options of verify attestation
   */
  verifyAttest(verifyAttestationOptions: VerifyAttestationOptions): VerifyAttestationOptions {
    return verifyAttestationOptions;
  }
}
