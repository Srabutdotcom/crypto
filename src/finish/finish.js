//@ts-self-types="../../type/finish/finish.d.ts"
import { Handshake, hmac, sha256, sha384 } from "../dep.ts";
import { HMAC, SHA256, SHA384 } from "../dep.ts";
import { Transcript } from "../secret/transcript.js";

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
   return new Uint8Array(finished_0);
}

export function finish_noble(finish_key, message, sha = 256) {
   const hash = sha == 256 ? sha256 :
      sha == 384 ? sha384 : sha256;

   const msgHash = hash.create()
      .update(message)
      .digest();

   const finished_0 = hmac
      .create(hash, finish_key)
      .update(msgHash)
      .digest();

   return finished_0
}

export function finish_stablelib(finish_key, message, sha = 256) {
   const hash = sha == 256 ? SHA256 :
      sha == 384 ? SHA384 : SHA256;

   const msgHash = new hash()
      .update(message)
      .digest()

   const finished_0 = new HMAC(hash, finish_key)
      .update(msgHash)
      .digest();

   return finished_0
}

//NOTE finish_noble is the fastest

export async function finished(finish_key, message, sha) {
   const funcs = [finish_noble, finish_stablelib, finish_web];
   let lastError;
   for (const func of funcs) {
      try {
         return await tries(func, finish_key, message, sha)
      } catch (error) {
         lastError = error;
      }
   }
   throw lastError
}

async function tries(func, ...args) {
   try {
      return await func(...args);
   } catch (error) {
      throw error
   }
}

export async function verifyFinished(key, transcript = Transcript, finishedMsg) {
   const sha = transcript.serverHelloMsg.message.cipher.hashLength * 8;
   const finished_0 = await finished(key, transcript.byte, sha);
   transcript.insert(finishedMsg)
   return new IsTrue(finished_0.toString() == finishedMsg.message.toString(), transcript)
}

class IsTrue extends Boolean {
   #data
   constructor(bool, data) {
      super(bool);
      this.#data = data
   }
   get data() {
      return this.#data
   }
}

export async function createFinished(key, transcript = Transcript) {
   const sha = transcript.serverHelloMsg.message.cipher.hashLength * 8;
   const finished_0 = await finished(key, transcript.byte, sha);
   const finished_0Msg = Handshake.fromFinished(finished_0);
   //transcript.insert(finished_0Msg);
   return finished_0Msg;
}
