import { HexaDecimal, hkdf, sha256 } from "../src/dep.ts";
import { EarlySecret } from "../src/hkdf/hkdf.js";
import { derivedSecret } from "../src/keyschedule/keyschedule.js";
import { assertEquals } from "jsr:@std/assert"


Deno.test("derived secret", ()=>{
   const test = hkdf.expand(
      sha256, 
      HexaDecimal.fromString(`33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2
            10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a`).byte,
      HexaDecimal.fromString(`00 20 0d 74 6c 73 31 33 20 64 65 72 69 76 65 64
            20 e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4
            64 9b 93 4c a4 95 99 1b 78 52 b8 55`).byte,
      32
   )
   
   const derived = derivedSecret(EarlySecret.SHA256, 'derived')
   assertEquals(test.toString(), derived.toString())
})

const derived_secret256_original = derivedSecret(EarlySecret.SHA256, 'derived');
const derived_secret256_default = Uint8Array.of(111,38,21,161,8,199,2,197,103,143,84,252,157,186,182,151,22,192,118,24,156,72,37,12,235,234,195,87,108,54,17,186)

const derived_secret384_original = derivedSecret(EarlySecret.SHA384, 'derived');
const derived_secret384_default = Uint8Array.of(115,123,52,69,75,237,139,131,80,43,54,16,80,167,99,154,146,146,198,59,140,7,137,209,122,146,113,108,234,67,141,183,30,88,208,165,51,240,17,149,152,60,244,110,133,34,78,95)




