import { EarlySecret, hkdfExtract256 } from "../src/hkdf/hkdf.js";
import { assertEquals } from "jsr:@std/assert"

Deno.test("hkdfExtract256", ()=>{
   const test = hkdfExtract256();
   assertEquals(test.toString(), EarlySecret.SHA256.toString())
})