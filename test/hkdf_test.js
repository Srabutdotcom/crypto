import { hkdfExtract384 } from "../src/hkdf/hkdf.js";
import { hkdfExtract } from "../src/hkdf/hkdf.js";
import { EarlySecret, hkdfExtract256 } from "../src/hkdf/hkdf.js";
import { assertEquals } from "jsr:@std/assert"

Deno.test("hkdfExtract256", ()=>{
   const test = hkdfExtract256();
   assertEquals(test.toString(), EarlySecret.SHA256.toString())
})

const test = hkdfExtract384();
assertEquals(test.toString(), EarlySecret.SHA384.toString())

const test_1 = await hkdfExtract(384, new Uint8Array, new Uint8Array);

const n = null;
