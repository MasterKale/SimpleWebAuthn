export enum ATTESTATION_FORMATS {
  FIDO_U2F = 'fido-u2f',
  PACKED = 'packed',
  ANDROID_SAFETYNET = 'android-safetynet',
  NONE = 'none',
};

/**
 * U2F Presence constant
 */
export const U2F_USER_PRESENTED = 0x01;

export const COSEKEYS = {
  'kty' : 1,
  'alg' : 3,
  'crv' : -1,
  'x'   : -2,
  'y'   : -3,
  'n'   : -1,
  'e'   : -2
}

export const COSEKTY = {
  'OKP': 1,
  'EC2': 2,
  'RSA': 3
}

export const COSERSASCHEME = {
  '-3': 'pss-sha256',
  '-39': 'pss-sha512',
  '-38': 'pss-sha384',
  '-65535': 'pkcs1-sha1',
  '-257': 'pkcs1-sha256',
  '-258': 'pkcs1-sha384',
  '-259': 'pkcs1-sha512'
}

export const COSEALGHASH = {
  '-257': 'sha256',
  '-258': 'sha384',
  '-259': 'sha512',
  '-65535': 'sha1',
  '-39': 'sha512',
  '-38': 'sha384',
  '-37': 'sha256',
  '-7': 'sha256',
  '-8': 'sha512',
  '-36': 'sha512'
}

export const COSECRV = {
  1: 'p256',
  2: 'p384',
  3: 'p521',
};

/**
 * This "GS Root R2" root certificate was downloaded from https://pki.goog/gsr2/GSR2.crt
 * on 08/10/2019 and then run through `base64url.encode()` to get this representation.
 *
 * The certificate is valid until Dec 15, 2021
 */
export const GlobalSignRootCAR2 = 'MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6-Lm8omUVCxKs-IVSbC9N_hHD6ErPLv4dfxn-G07IwXNb9rfF73OX4YJYJkhD10FPe-3t-c4isUoh7SqbKSaZeqKeMWhG8eoLrvozps6yWJQeXSpkqBy-0Hne_ig-1AnwblrjFuTosvNYSuetZfeLQBoZfXklqtTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzdC9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ_gkwpRl4pazq-r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCBmTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH_BAUwAwEB_zAdBgNVHQ4EFgQUm-IHV2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4GsJ0_WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO291xNBrBVNpGP-DTKqttVCL1OmLNIG-6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavSot-3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h-u_N5GJG79G-dwfCMNYxdAfvDbbnvRG15RjF-Cv6pgsH_76tuIMRQyV-dTZsXjAzlAcmgQWpzU_qlULRuJQ_7TBj0_VLZjmmx6BEP3ojY-x1J96relc8geMJgEtslQIxq_H5COEBkEveegeGTLg';
