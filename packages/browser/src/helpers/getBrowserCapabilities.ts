/**
 * A helper method that wraps WebAuthn's
 * [`PublicKeyCredential.getClientCapabilities()`](https://w3c.github.io/webauthn/#sctn-getClientCapabilities)
 * feature detection method. This method includes efforts to determine a feature's availability if a
 * browser reports an "unknown" level of support for it but there exists an alternative WebAuthn API
 * that reports the feature's availability.
 *
 * Capabilities are mapped to one of the following values:
 *
 * - **supported**: The browser supports the capability
 * - **unsupported**: The browser does not support the capability
 * - **unknown**: The browser may or may not support the capability, try it and see
 *
 * **Note:** If a WebAuthn client other than the browser is handling WebAuthn API calls (e.g. a
 * password manager's browser extension) then this method will report that client's capabilities
 * instead (assuming that client has implemented `PublicKeyCredential.getClientCapabilities()`.)
 */
export async function getBrowserCapabilities(): Promise<BrowserCapabilities> {
  if (typeof PublicKeyCredential.getClientCapabilities === 'function') {
    const capabilities = await PublicKeyCredential
      .getClientCapabilities() as PublicKeyCredentialClientCapabilities;

    /**
     * The `userVerifyingPlatformAuthenticator` capability and `isUVPAA()` return value are
     * equivalent, so we can fall back to the value of the latter when the capability is unknown.
     *
     * https://w3c.github.io/webauthn/#dom-clientcapability-userverifyingplatformauthenticator
     */
    let _userVerifyingPlatformAuthenticator = mapCapabilityToEnum(
      capabilities.userVerifyingPlatformAuthenticator,
    );

    if (
      _userVerifyingPlatformAuthenticator === 'unknown' &&
      typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function'
    ) {
      const isUVPAA = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      if (isUVPAA) {
        _userVerifyingPlatformAuthenticator = 'supported';
      } else {
        _userVerifyingPlatformAuthenticator = 'unsupported';
      }
    }

    /**
     * The `conditionalGet` capability and `isConditionalMediationAvailable()` return value are
     * equivalent, so we can fall back to the value of the latter when the capability is unknown.
     *
     * https://w3c.github.io/webauthn/#dom-clientcapability-conditionalget
     */
    let _conditionalGet = mapCapabilityToEnum(capabilities.conditionalGet);
    if (
      _conditionalGet === 'unknown' &&
      typeof PublicKeyCredential.isConditionalMediationAvailable === 'function'
    ) {
      const isCMA = await PublicKeyCredential.isConditionalMediationAvailable();
      if (isCMA) {
        _conditionalGet = 'supported';
      } else {
        _conditionalGet = 'unsupported';
      }
    }

    return _getBrowserCapabilitiesInternals.stubThis({
      conditionalCreate: mapCapabilityToEnum(capabilities.conditionalCreate),
      conditionalGet: _conditionalGet,
      hybridTransport: mapCapabilityToEnum(capabilities.hybridTransport),
      passkeyPlatformAuthenticator: mapCapabilityToEnum(capabilities.passkeyPlatformAuthenticator),
      userVerifyingPlatformAuthenticator: _userVerifyingPlatformAuthenticator,
      relatedOrigins: mapCapabilityToEnum(capabilities.relatedOrigins),
      signalAllAcceptedCredentials: mapCapabilityToEnum(capabilities.signalAllAcceptedCredentials),
      signalCurrentUserDetails: mapCapabilityToEnum(capabilities.signalCurrentUserDetails),
      signalUnknownCredential: mapCapabilityToEnum(capabilities.signalUnknownCredential),
    });
  }

  return _getBrowserCapabilitiesInternals.stubThis({
    conditionalCreate: 'unknown',
    conditionalGet: 'unknown',
    hybridTransport: 'unknown',
    passkeyPlatformAuthenticator: 'unknown',
    userVerifyingPlatformAuthenticator: 'unknown',
    relatedOrigins: 'unknown',
    signalAllAcceptedCredentials: 'unknown',
    signalCurrentUserDetails: 'unknown',
    signalUnknownCredential: 'unknown',
  });
}

/**
 * One of the following values:
 *
 * - **supported**: The browser supports the corresponding capability
 * - **unsupported**: The browser does not support the corresponding capability
 * - **unknown**: The browser may or may not support the capability, try it and see
 */
export type BrowserCapabilitySupport = 'supported' | 'unsupported' | 'unknown';

/**
 * Various WebAuthn features the browser may support. See each property's description for more info.
 */
export type BrowserCapabilities = {
  /** The browser can facilitate silent passkey registration after a successful auth */
  conditionalCreate: BrowserCapabilitySupport;
  /** The browser supports autofill UI to present available passkeys */
  conditionalGet: BrowserCapabilitySupport;
  /** The browser can communicate with another device via the hybrid transport to use a passkey */
  hybridTransport: BrowserCapabilitySupport;
  /** The browser can use a local platform authenticator, or a platform authenticator available on another device via the hybrid transport  */
  passkeyPlatformAuthenticator: BrowserCapabilitySupport;
  /** The browser can use a locally available user-verifying platform authenticator */
  userVerifyingPlatformAuthenticator: BrowserCapabilitySupport;
  /** The browser can facilitate use of a passkey, bound to one RP ID, across different origins */
  relatedOrigins: BrowserCapabilitySupport;
  /** The browser supports the signal API that communicates the user's current allowed passkeys for this site */
  signalAllAcceptedCredentials: BrowserCapabilitySupport;
  /** The browser supports the signal API that communicates the user's current metadata */
  signalCurrentUserDetails: BrowserCapabilitySupport;
  /** The browser supports the signal API that communicates an invalid credential ID */
  signalUnknownCredential: BrowserCapabilitySupport;
};

/**
 * Typing specific to the PublicKeyCredential.getClientCapabilities() method that's being wrapped
 * above. A capability with an `undefined` value does not mean the feature is unsupported. It may
 * simply be that the browser has chosen not to divulge its support for the capability as a more
 * specific determination may be factored into e.g. ad-tech's browser fingerprinting that violates
 * user privacy against the goals of the browser.
 */
type PublicKeyCredentialClientCapabilities = {
  conditionalCreate?: boolean;
  conditionalGet?: boolean;
  hybridTransport?: boolean;
  passkeyPlatformAuthenticator?: boolean;
  userVerifyingPlatformAuthenticator?: boolean;
  relatedOrigins?: boolean;
  signalAllAcceptedCredentials?: boolean;
  signalCurrentUserDetails?: boolean;
  signalUnknownCredential?: boolean;
};

/**
 * Map the tri-state booleans in `PublicKeyCredential.getClientCapablities()` to more descriptive
 * values instead.
 */
function mapCapabilityToEnum(value?: boolean): BrowserCapabilitySupport {
  if (value === true) {
    return 'supported';
  } else if (value === false) {
    return 'unsupported';
  } else if (typeof value === 'undefined') {
    return 'unknown';
  } else {
    throw new Error('Unexpected capability value:', value);
  }
}

// Make it possible to stub the return value during testing
export const _getBrowserCapabilitiesInternals = {
  stubThis: (value: BrowserCapabilities) => value,
};
