import { p256, safeuint8array, SignatureScheme } from "../src/dep.ts";
import { HexaDecimal } from "../src/dep.ts";
import asn1 from "asn1.js"
import { Buffer } from 'node:buffer';
import { secp256k1 } from "@noble/curves/secp256k1"
import * as utils from '@noble/curves/abstract/utils';
import { DERSignature } from "./der.js";

SignatureScheme.ECDSA_SECP256R1_SHA256.name.startsWith("ECDSA"); 

// Define the ASN.1 schema for the ECDSA signature
const ECDSASignature = asn1.define('ECDSASignature', function () {
   this.seq().obj(
      this.key('r').int(),
      this.key('s').int()
   );
});

const publicKey = Uint8Array.of(48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 38, 162, 174, 254, 143, 198, 214, 120, 131, 221, 4, 171, 43, 24, 182, 231, 145, 147, 38, 169, 170, 37, 252, 58, 185, 152, 244, 193, 77, 53, 183, 208, 160, 141, 183, 183, 18, 58, 0, 117, 31, 35, 234, 27, 229, 71, 234, 155, 145, 79, 126, 42, 186, 163, 101, 42, 249, 253, 211, 123, 245, 182, 56, 148);

const signature = Uint8Array.of(48, 69, 2, 32, 80, 218, 222, 190, 170, 243, 8, 242, 119, 98, 215, 176, 81, 134, 141, 125, 56, 227, 154, 144, 2, 189, 56, 121, 222, 178, 94, 130, 44, 30, 4, 216, 2, 33, 0, 206, 50, 95, 183, 151, 179, 190, 20, 194, 22, 82, 159, 208, 156, 186, 12, 190, 152, 100, 102, 10, 116, 201, 222, 237, 217, 87, 237, 105, 168, 219, 220)

const data = Uint8Array.of(32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 84, 76, 83, 32, 49, 46, 51, 44, 32, 115, 101, 114, 118, 101, 114, 32, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 86, 101, 114, 105, 102, 121, 0, 62, 111, 114, 174, 123, 76, 57, 67, 41, 108, 228, 102, 252, 129, 52, 160, 116, 156, 138, 248, 64, 159, 173, 102, 179, 241, 148, 182, 29, 146, 181, 142)

Deno.bench("Using asn1.js", () => {
   const signatureRS = derToRS(Buffer.from(signature));
   const signatureByte_0 = safeuint8array(
      HexaDecimal.fromString(signatureRS.r).byte,
      HexaDecimal.fromString(signatureRS.s).byte,
   )
})

Deno.bench("Using noble", () => {
   const signatureRSNoble = secp256k1.Signature.fromDER(signature);
   const r = utils.numberToBytesBE(signatureRSNoble.r);
   const s = utils.numberToBytesBE(signatureRSNoble.s);
   const signatureByte_1 = safeuint8array(r, s)
})

Deno.bench("Using my own", ()=>{
   const signatureByte_2 = DERSignature.from(signature).rs;
})

const isValid = p256.verify(
   signature,
   data,
   publicKey
);
console.log(isValid)

const isValid_0 = await verify(publicKey, DERSignature.from(signature).rs, data)
console.log(isValid_0)

async function importKey(publicKey) {
   return await crypto.subtle.importKey(
      "spki",//"raw",//
      publicKey,
      {
         name: "ECDSA",//"RSA-PSS",//"ECDH",//
         namedCurve: "P-256"
         //hash: "SHA-256"
      },//cert.signatureAlgorithm,//cert.publicKey.algorithm, 
      true,
      ["verify"])
}

async function verify(publicKey, signature, data) {
   return await crypto.subtle.verify(
      {
         name: "ECDSA",//"RSA-PSS",//
         //saltLength: 32
         hash: "SHA-256"
      }, //publicKey.algorithm,//
      await importKey(publicKey),
      signature,
      data
   )
}

// Function to convert DER to R and S
function derToRS(derSignature) {
   const decoded = ECDSASignature.decode(derSignature, 'der');
   return {
      r: decoded.r.toString(16),
      s: decoded.s.toString(16)
   };
}

debugger;
