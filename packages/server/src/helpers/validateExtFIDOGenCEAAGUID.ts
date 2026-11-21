import { AsnParser, OctetString } from '@peculiar/asn1-schema';
import type { Extensions } from '@peculiar/asn1-x509';

import { isoUint8Array } from './iso/index.ts';
import type { Uint8Array_ } from '../types/index.ts';
import { SimpleWebAuthnError } from '../errors/index.ts';

/**
 * Attestation Certificate Extension OID: `id-fido-gen-ce-aaguid`
 *
 * Sourced from https://fidoalliance.org/specs/fido-v2.0-ps-20150904/fido-key-attestation-v2.0-ps-20150904.html#verifying-an-attestation-statement
 */
const id_fido_gen_ce_aaguid = '1.3.6.1.4.1.45724.1.1.4';

/**
 * Look for the id-fido-gen-ce-aaguid certificate extension. If it's present then check it against
 * the attestation statement AAGUID.
 */
export function validateExtFIDOGenCEAAGUID(
  certExtensions: Extensions | undefined,
  aaguid: Uint8Array_,
): boolean {
  // The certificate had no extensions so there's nothing to validate
  if (!certExtensions) {
    return true;
  }

  const extFIDOGenCEAAGUID = certExtensions.find((ext) => ext.extnID === id_fido_gen_ce_aaguid);

  // The extension isn't present so there's nothing to validate
  if (!extFIDOGenCEAAGUID) {
    return true;
  }

  /**
   * This extension must not be marked critical.
   *
   * See https://w3c.github.io/webauthn/#sctn-packed-attestation-cert-requirements:~:text=If%20the%20related%20attestation%20root%20certificate%20is%20used%20for%20multiple%20authenticator%20models%2C%20the%20Extension%20OID%201.3.6.1.4.1.45724.1.1.4%20(id%2Dfido%2Dgen%2Dce%2Daaguid)%20MUST%20be%20present%2C%20containing%20the%20AAGUID%20as%20a%2016%2Dbyte%20OCTET%20STRING.%20The%20extension%20MUST%20NOT%20be%20marked%20as%20critical.
   */
  if (extFIDOGenCEAAGUID.critical) {
    throw new SimpleWebAuthnError({
      message: 'id-fido-gen-ce-aaguid extension was present but marked critical',
      code: 'INVALID_X509_CERTIFICATE',
    });
  }

  // Parse the extension value
  const parsedExtFIDOGenCEAAGUID = AsnParser.parse(extFIDOGenCEAAGUID.extnValue, OctetString);
  const extValue = new Uint8Array(parsedExtFIDOGenCEAAGUID.buffer);

  // Compare the two values
  const aaguidAndExtAreEqual = isoUint8Array.areEqual(aaguid, extValue);

  if (!aaguidAndExtAreEqual) {
    const _debugExtHex = isoUint8Array.toHex(extValue);
    const _debugAAGUIDHex = isoUint8Array.toHex(aaguid);
    throw new Error(
      `Certificate extension id-fido-gen-ce-aaguid (${id_fido_gen_ce_aaguid}) value of "${_debugExtHex}" was present but not equal to attestation statement AAGUID value of "${_debugAAGUIDHex}"`,
    );
  }

  return true;
}
