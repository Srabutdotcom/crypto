//@ts-self-types="../../type/finish/finish.d.ts"
import { Finished, hmac, sha256, sha384 } from "../dep.ts";
import { HMAC, SHA256, SHA384 } from "../dep.ts";

export async function finish_web(finish_key, message, sha = 256) {
   const key = await crypto.subtle.importKey(
      "raw",
      finish_key,
      {
         name: "HMAC",
         hash: { name: `SHA-${sha}` },
      },
      true,
      ["sign", "verify"]
   );

   const msgHash = await crypto.subtle.digest(`SHA-${sha}`, message);

   const finished_0 = await crypto.subtle.sign(
      { name: "HMAC" },
      key,
      msgHash
   )

   /* const _test_verify_data = await crypto.subtle.verify(
      { name: "HMAC" },
      key,
      finished_0,
      msgHash
   ) */
   return new Uint8Array(finished_0);
}

export function finish_noble(finish_key, message, sha = 256) {
   const hash = sha == 256 ? sha256 :
      sha == 384 ? sha384 : sha256;

   const msgHash = hash.create()
      .update(message)
      .digest();

   const finished = hmac
      .create(hash, finish_key)
      .update(msgHash)
      .digest();

   return finished
}

export function finish_stablelib(finish_key, message, sha = 256) {
   const hash = sha == 256 ? SHA256 :
      sha == 384 ? SHA384 : SHA256;

   const msgHash = new hash()
   .update(message)
   .digest()

   const finished = new HMAC(hash, finish_key)
   .update(msgHash)
   .digest();

   return finished
}

//NOTE finish_noble is the fastest

export async function finished(finish_key, message, sha){
   const funcs = [ finish_noble, finish_stablelib, finish_web ];
   let lastError;
   for (const func of funcs){
      try {
         return await tries(func, finish_key, message, sha)
      } catch (error) {
         lastError = error;
      }
   }
   throw lastError
}

async function tries(func, ...args){
   try {
      return await func(...args);
   } catch (error) {
      throw error
   }
}
