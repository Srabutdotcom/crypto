//@ts-self-types="../../type/hkdf/hkdf.d.ts"
import { Crypto, hkdf, sha256, sha384, sha512, Enum } from "../dep.ts";
import { concatOctet } from "../dep.ts";

const crypto = new Crypto();

export async function hkdfExtract(hashBitLength=256, ikm = new Uint8Array, salt= new Uint8Array){
   if(salt.length==0)salt = new Uint8Array(hashBitLength/8);
   if(ikm.length==0)ikm = new Uint8Array(hashBitLength/8);
   const baseKey = await crypto.subtle.importKey("raw", salt, { name: "HMAC", hash: `SHA-${hashBitLength}` }, false, ["sign", "verify"])
   const derivedKey = await crypto.subtle.sign({ name: "HMAC" }, baseKey, ikm)
   return new Uint8Array(derivedKey)
}

export function hkdfExtract256(ikm = new Uint8Array(32), salt = new Uint8Array){
   return hkdf.extract(sha256, ikm, salt)
}

export function hkdfExtract384(ikm = new Uint8Array(48), salt = new Uint8Array){
   return hkdf.extract(sha384, ikm, salt)
}

export function hkdfExtract512(ikm = new Uint8Array(64), salt = new Uint8Array){
   return hkdf.extract(sha512, ikm, salt)
}

export class EarlySecret extends Enum {
   static SHA512 = new EarlySecret("SHA512", Uint8Array.of(253,74,64,203,98,82,179,192,141,155,136,213,189,232,83,57,3,202,165,26,29,186,28,121,206,24,238,160,54,93,53,208,113,229,151,162,185,82,20,130,17,0,232,18,247,183,152,40,73,143,22,71,7,205,99,198,247,70,73,115,207,162,32,70))
   static SHA384 = new EarlySecret("SHA384", Uint8Array.of(126,232,32,111,85,112,2,62,109,199,81,158,177,7,59,196,231,145,173,55,181,195,130,170,16,186,24,226,53,126,113,105,113,249,54,47,44,47,226,167,107,253,120,223,236,78,169,181))
   static SHA256 = new EarlySecret("SHA256", Uint8Array.of(51,173,10,28,96,126,192,59,9,230,205,152,147,104,12,226,16,173,243,0,170,31,38,96,225,178,46,16,241,112,249,42))
} 

export async function hkdfExpand(prk, info, hashByteLength){
   let t = new Uint8Array;
   let okm = new Uint8Array;
   let i = 0;
   while(okm.length < hashByteLength){
      i++;
      const counter = Uint8Array.of(i);
      const input = concatOctet(t, info, counter);
      t = await hkdfExtract(hashByteLength, prk, input); 
      okm = concatOctet(okm, t)
   }
   return okm.slice(0, hashByteLength)
}
