import {
  AuthenticationExtensionsClientOutputsJSON,
  AuthenticationExtensionsClientOutputsFuture,
  RegistrationCredential,
  AuthenticationCredential
} from "@simplewebauthn/typescript-types";
import { bufferToBase64URLString } from "./bufferToBase64URLString";

export function parseClientExtensionResults(
  credential: AuthenticationCredential | RegistrationCredential
): AuthenticationExtensionsClientOutputsJSON {
  const clientExtensionResults: AuthenticationExtensionsClientOutputsFuture = credential.getClientExtensionResults()
  const clientExtensionResultsJSON: AuthenticationExtensionsClientOutputsJSON = {};

  for (const key in clientExtensionResults) {
    if (key === 'appid') {
      clientExtensionResultsJSON.appid = clientExtensionResults.appid;
    } else if (key === 'credProps') {
      clientExtensionResultsJSON.credProps = clientExtensionResults.credProps;
    } else if (key === 'devicePubKey') {
      const { devicePubKey } = clientExtensionResults;
      if (!devicePubKey) continue;
      const authenticatorOutput = bufferToBase64URLString(devicePubKey.authenticatorOutput);
      const signature = bufferToBase64URLString(devicePubKey.signature);
      clientExtensionResultsJSON.devicePubKey = { authenticatorOutput, signature };
    } else if (key === 'uvm') {
      clientExtensionResultsJSON.uvm = clientExtensionResults.uvm;
    }
  }

  return clientExtensionResultsJSON;
}
