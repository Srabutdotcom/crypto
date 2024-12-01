import * as hkdf from "@noble/hashes/hkdf"
import { sha256, sha384, sha512 } from "@noble/hashes/sha2"
import { hkdfExtract } from "../src/hkdf/hkdf.js";

Deno.bench("hkdfExtract",async()=>{
   const earlySecret = await hkdfExtract(256);
})

Deno.bench("hkdf", ()=>{
   const earlySecret2 = hkdf.extract(sha256, new Uint8Array(256/8))

})

Deno.bench("default", ()=>{
   const sha256 = Uint8Array.of(51,173,10,28,96,126,192,59,9,230,205,152,147,104,12,226,16,173,243,0,170,31,38,96,225,178,46,16,241,112,249,42)
})