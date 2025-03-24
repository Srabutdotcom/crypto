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
   
   const derived = derivedSecret(EarlySecret.SHA256, 'derived', new Uint8Array(), 32)
   assertEquals(test.toString(), derived.toString())
})

const derived_secret256_original = derivedSecret(EarlySecret.SHA256, 'derived', new Uint8Array, 32);
const derived_secret256_default = Uint8Array.of(111,38,21,161,8,199,2,197,103,143,84,252,157,186,182,151,22,192,118,24,156,72,37,12,235,234,195,87,108,54,17,186)

const derived_secret384_original = derivedSecret(EarlySecret.SHA384, 'derived', new Uint8Array, 48);
const derived_secret384_default = Uint8Array.of(21,145,218,197,203,191,3,48,164,168,77,233,199,83,51,14,146,208,31,10,136,33,75,68,100,151,47,214,104,4,158,147,229,47,43,22,250,217,34,253,192,88,68,120,66,143,40,43)

const _null = null




