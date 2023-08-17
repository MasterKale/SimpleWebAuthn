import { assertEquals } from "https://deno.land/std@0.198.0/assert/mod.ts";

import { convertAAGUIDToString } from "./convertAAGUIDToString.ts";
import { isoUint8Array } from "./iso/index.ts";

Deno.test("should convert buffer to UUID string", () => {
  const uuid = convertAAGUIDToString(
    isoUint8Array.fromHex("adce000235bcc60a648b0b25f1f05503"),
  );

  assertEquals(uuid, "adce0002-35bc-c60a-648b-0b25f1f05503");
});
