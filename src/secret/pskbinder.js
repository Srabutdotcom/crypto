import { sha256, sha384 } from "../dep.ts";
import { hkdfExtract384 } from "../hkdf/hkdf.js";
import { hkdfExtract256 } from "../hkdf/hkdf.js";
import { hkdfExpandLabel } from "../keyschedule/keyschedule.js";
import { derivedSecret } from "../keyschedule/keyschedule.js";
import { PskBinderEntry, Binders } from "../dep.ts"

async function finished(resumptionKey, sha = 256, clientHelloMsg) {
   const hkdfExtract = sha == 256 ? hkdfExtract256 : sha == 384 ? hkdfExtract384 : hkdfExtract256
   const earlyKey = hkdfExtract(Uint8Array.of(), resumptionKey); 
   const binderKey = derivedSecret(earlyKey, "res binder", Uint8Array.of()); // prk
   const finishKey =  hkdfExpandLabel(binderKey, 'finished', Uint8Array.of()); // expanded.
   
   //const finishedKey = hkdfExpandLabel(serverHS_secret, 'finished', new Uint8Array, 32);
   const finishedKeyCrypto = await crypto.subtle.importKey(
      "raw",
      finishKey,
      {
         name: "HMAC",
         hash: { name: `SHA-${sha}` },
      },
      true,
      ["sign", "verify"]
   );

   const hash = sha == 256 ? sha256.create() :
      sha == 384 ? sha384.create() : sha256.create();

   const transcriptHash = hash
      .update(clientHelloMsg)
      .digest();

   const finished_0 = await crypto.subtle.sign(
      { name: "HMAC" },
      finishedKeyCrypto,
      transcriptHash
   )

   /* const _test_verify_data = await crypto.subtle.verify(
      { name: "HMAC" },
      finishedKeyCrypto,
      verify_data,
      transcriptHash
   ) */
   //verify_data.transcriptHash = transcriptHash;
   return new Uint8Array(finished_0);
}

export async function binders(clientHelloMsg, sha = 256, ...resumptionKeys) {
   const binders = [];
   for(const key of resumptionKeys){
      const finished_0 = await finished(key, sha, clientHelloMsg) 
      const binder = PskBinderEntry.fromBinderEntry(finished_0);
      binders.push(binder)
   }
   return Binders.fromBinders(...binders)
}