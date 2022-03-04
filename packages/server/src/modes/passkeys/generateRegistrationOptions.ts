import {
  AuthenticatorSelectionCriteria,
  PublicKeyCredentialCreationOptionsJSON,
} from '@simplewebauthn/typescript-types';

import _generateRegistrationOptions, {
  GenerateRegistrationOptionsOpts,
}
from '../../registration/generateRegistrationOptions';


export function generateRegistrationOptions(
  options: GenerateRegistrationOptionsOpts,
): PublicKeyCredentialCreationOptionsJSON {
  const { authenticatorSelection, ...rest } = options;

  const pwlAuthenticatorSelection: AuthenticatorSelectionCriteria = {
    ...authenticatorSelection,
    userVerification: 'required',
  };

  return _generateRegistrationOptions({
    ...rest,
    authenticatorSelection: pwlAuthenticatorSelection,
  });
}
