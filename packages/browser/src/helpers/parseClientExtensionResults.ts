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

  const { appid, credProps, devicePubKey, uvm } = clientExtensionResults;

  if (appid) {
    clientExtensionResultsJSON.appid = appid;
  }

  if (credProps) {
    clientExtensionResultsJSON.credProps = credProps;
  }

  if (uvm) {
    clientExtensionResultsJSON.uvm = clientExtensionResults.uvm;
  }

  if (devicePubKey) {
    clientExtensionResultsJSON.devicePubKey = {
      authenticatorOutput: bufferToBase64URLString(devicePubKey.authenticatorOutput),
      signature: bufferToBase64URLString(devicePubKey.signature),
    };
  }

  return clientExtensionResultsJSON;
}
