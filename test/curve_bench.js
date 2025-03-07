import { p256, p384, p521, x25519 } from "../src/dep.ts";
import elliptic from "elliptic"

Deno.bench("Generate ECDSA P-384 Key using webcrypto Api", async ()=>{
   const keys = await crypto.subtle.generateKey(
      {
         name: "ECDH",
         namedCurve: "P-384"
      },
      true, 
      ["deriveBits"]
   )
})

Deno.bench("Generate ECDSA P-384 Key using elliptic", ()=>{
   var EC = elliptic.ec;
   var ec = new EC('p384');
   // generate keys
   var keys = ec.genKeyPair();
})

Deno.bench("Generate ECDSA P-384 Key using noble", ()=>{
   const priv = p384.utils.randomPrivateKey();
})

const keys_1 = await crypto.subtle.generateKey(
   {
      name: "ECDH",
      namedCurve: "P-384"
   },
   true, 
   ["deriveBits"]
);

const keys_2 = await crypto.subtle.generateKey(
   {
      name: "ECDH",
      namedCurve: "P-384"
   },
   true, 
   ["deriveBits"]
);

const sharedKey = await crypto.subtle.deriveBits(
   {
      name: "ECDH",
      public: keys_2.publicKey
   },
   keys_1.privateKey,
   384
)

const priv = p384.utils.randomPrivateKey();
const pub  = p384.getPublicKey(priv, false);

