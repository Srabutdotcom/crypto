import * as hkdf from "@noble/hashes/hkdf"
import { sha256, sha384, sha512 } from "@noble/hashes/sha2"
import { EarlySecret } from "../src/hkdf/hkdf.js"
import { hkdfExpand } from "../src/hkdf/hkdf.js"

const rnd = crypto.getRandomValues(new Uint8Array(32))

Deno.bench("hkdf.expand",()=>{
   const test = hkdf.expand(sha256,EarlySecret.SHA256,rnd,32)
})

Deno.bench("hkdfExpand",async()=>{
   const test2 = await hkdfExpand(EarlySecret.SHA256,rnd, 256)
})



