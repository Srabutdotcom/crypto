//@ts-self-types="../../type/hkdf/hkdf.d.ts"
import { /* Crypto,  */hkdf, sha256, sha384 } from "../dep.ts";
import { safeuint8array } from "../dep.ts";

//const crypto = new Crypto();

export async function hkdfExtract(hashBitLength=256, ikm = new Uint8Array, salt= new Uint8Array){
   if(salt.length==0)salt = new Uint8Array(hashBitLength/8);
   if(ikm.length==0)ikm = new Uint8Array(hashBitLength/8);
   const baseKey = await crypto.subtle.importKey("raw", salt, { name: "HMAC", hash: `SHA-${hashBitLength}` }, false, ["sign", "verify"])
   const derivedKey = await crypto.subtle.sign({ name: "HMAC" }, baseKey, ikm)
   return new Uint8Array(derivedKey)
}

export function hkdfExtract256(salt = new Uint8Array, ikm = new Uint8Array(32)){
   return hkdf.extract(sha256, ikm, salt)
}

export function hkdfExtract384(salt = new Uint8Array, ikm = new Uint8Array(48)){
   return hkdf.extract(sha384, ikm, salt)
}

/**
 * derived from hkdfExtract() without argument.
 */
export class EarlySecret /* extends Enum */ {
   static SHA384 = /* new EarlySecret("SHA384", */ Uint8Array.of(126,232,32,111,85,112,2,62,109,199,81,158,177,7,59,196,231,145,173,55,181,195,130,170,16,186,24,226,53,126,113,105,113,249,54,47,44,47,226,167,107,253,120,223,236,78,169,181)/* ) */
   static SHA256 = /* new EarlySecret("SHA256", */ Uint8Array.of(51,173,10,28,96,126,192,59,9,230,205,152,147,104,12,226,16,173,243,0,170,31,38,96,225,178,46,16,241,112,249,42)/* ) */
} 

export async function hkdfExpand(prk, info, hashBitLength){
   const hashByteLength = hashBitLength / 8
   let t = new Uint8Array;
   let okm = new Uint8Array;
   let i = 0;
   while(okm.length < hashByteLength){
   //for(let i = 1; okm.length < hashByteLength; i++){
      i++;
      const counter = Uint8Array.of(i);
      const input = safeuint8array(t, info, counter);
      t = await hkdfExtract(hashBitLength, input, prk); 
      okm = safeuint8array(okm, t)
   }
   return okm.slice(0, hashByteLength)
}
