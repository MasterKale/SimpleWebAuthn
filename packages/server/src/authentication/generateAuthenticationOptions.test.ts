import {
  assert,
  assertEquals,
  assertExists,
} from "https://deno.land/std@0.198.0/assert/mod.ts";

import { isoBase64URL, isoUint8Array } from "../helpers/iso/index.ts";

import { generateAuthenticationOptions } from "./generateAuthenticationOptions.ts";

const challengeString = "dG90YWxseXJhbmRvbXZhbHVl";
const challengeBuffer = isoBase64URL.toBuffer(challengeString);

Deno.test("should generate credential request options suitable for sending via JSON", async () => {
  const options = await generateAuthenticationOptions({
    allowCredentials: [
      {
        id: isoUint8Array.fromASCIIString("1234"),
        type: "public-key",
        transports: ["usb", "nfc"],
      },
      {
        id: isoUint8Array.fromASCIIString("5678"),
        type: "public-key",
        transports: ["internal"],
      },
    ],
    timeout: 1,
    challenge: challengeBuffer,
  });

  assertEquals(options, {
    // base64url-encoded
    challenge: challengeString,
    allowCredentials: [
      {
        id: "MTIzNA",
        type: "public-key",
        transports: ["usb", "nfc"],
      },
      {
        id: "NTY3OA",
        type: "public-key",
        transports: ["internal"],
      },
    ],
    timeout: 1,
    userVerification: "preferred",
    extensions: undefined,
    rpId: undefined,
  });
});

Deno.test("defaults to 60 seconds if no timeout is specified", async () => {
  const options = await generateAuthenticationOptions({
    challenge: challengeBuffer,
    allowCredentials: [
      { id: isoUint8Array.fromASCIIString("1234"), type: "public-key" },
      { id: isoUint8Array.fromASCIIString("5678"), type: "public-key" },
    ],
  });

  assertEquals(options.timeout, 60000);
});

Deno.test('should set userVerification to "preferred" if not specified', async () => {
  const options = await generateAuthenticationOptions({
    challenge: challengeBuffer,
    allowCredentials: [
      { id: isoUint8Array.fromASCIIString("1234"), type: "public-key" },
      { id: isoUint8Array.fromASCIIString("5678"), type: "public-key" },
    ],
  });

  assertEquals(options.userVerification, "preferred");
});

Deno.test("should not set allowCredentials if not specified", async () => {
  const options = await generateAuthenticationOptions({ rpID: "test" });

  assertEquals(options.allowCredentials, undefined);
});

Deno.test("should generate without params", async () => {
  const options = await generateAuthenticationOptions();
  const { challenge, ...otherFields } = options;
  assertEquals(otherFields, {
    allowCredentials: undefined,
    extensions: undefined,
    rpId: undefined,
    timeout: 60000,
    userVerification: "preferred",
  });
  assertEquals(typeof challenge, "string");
});

Deno.test("should set userVerification if specified", async () => {
  const options = await generateAuthenticationOptions({
    challenge: challengeBuffer,
    allowCredentials: [
      { id: isoUint8Array.fromASCIIString("1234"), type: "public-key" },
      { id: isoUint8Array.fromASCIIString("5678"), type: "public-key" },
    ],
    userVerification: "required",
  });

  assertEquals(options.userVerification, "required");
});

Deno.test("should set extensions if specified", async () => {
  const options = await generateAuthenticationOptions({
    challenge: challengeBuffer,
    allowCredentials: [
      { id: isoUint8Array.fromASCIIString("1234"), type: "public-key" },
      { id: isoUint8Array.fromASCIIString("5678"), type: "public-key" },
    ],
    extensions: { appid: "simplewebauthn" },
  });

  assertEquals(options.extensions, { appid: "simplewebauthn" });
});

Deno.test("should generate a challenge if one is not provided", async () => {
  const opts = {
    allowCredentials: [
      { id: isoUint8Array.fromASCIIString("1234"), type: "public-key" },
      { id: isoUint8Array.fromASCIIString("5678"), type: "public-key" },
    ],
  };

  // @ts-ignore 2345
  const options = await generateAuthenticationOptions(opts);

  // Assert basic properties of the challenge
  assert(options.challenge.length >= 16);
  assert(isoBase64URL.isBase64url(options.challenge));
});

Deno.test("should set rpId if specified", async () => {
  const rpID = "simplewebauthn.dev";

  const opts = await generateAuthenticationOptions({
    allowCredentials: [],
    rpID,
  });

  assertExists(opts.rpId);
  assertEquals(opts.rpId, rpID);
});
