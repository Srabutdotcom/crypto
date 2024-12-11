//@ts-self-types="../../type/aead/aead.d.ts"
import { TLSCiphertext } from "../dep.ts"

export class Aead { //*AESGCM

   /**
    * @type {number} sequential number - positive integer
    */
   seq = 0

   /**
    * @type {Uint8Array} key - octet
    */
   key

   /**
    * @type {Uint8Array} iv - Uint8Array
    */
   iv

   /**
    * @type {{ name: "AES-GCM"; iv: Uint8Array; additionalData: Uint8Array; }} Algorithm 
    */
   algo = {
      name: "AES-GCM",
      iv: new Uint8Array,
      additionalData: new Uint8Array,
      //tagLength: 128 //*by default is 128
   }

   /**
    * @type {CryptoKey} key - CryptoKey
    */
   cryptoKey
   /**
    * 
    * @param {Uint8Array} key 
    * @param {Uint8Array} iv
    */
   constructor(key, iv) {
      this.key = key;
      this.iv = iv;
      this.algo.iv = iv
   }
   buildIV() {
      for (let i = 0; i < 8; i++) {
         this.iv[this.iv.length - 1 - i] ^= ((this.seq >> (i * 8)) & 0xFF);
      }
      this.seq++;
   }
   async importKey() {
      if (this.cryptoKey) return
      this.cryptoKey = await self.crypto.subtle.importKey('raw', this.key, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'])
   }
   /**
    * 
    * @param {TLSInnerPlaintext} tlsInnerPlaintext - data to be encrypted in Uint8Array
    * @returns {TLSCiphertext}
    */
   async encrypt(tlsInnerPlaintext) {
      const lengthOf = tlsInnerPlaintext.length + this.key.length;
      const header = Uint8Array.of(tlsInnerPlaintext.at(-1), 3, 3, Math.trunc(lengthOf / 256), lengthOf % 256)
      await this.importKey();
      this.algo = {
         name: "AES-GCM",
         iv: this.iv,
         additionalData: header, // as additional data
         //tagLength: 128 //*by default is 128
      }
      const output = await self.crypto.subtle.encrypt(this.algo, this.cryptoKey, tlsInnerPlaintext);
      this.buildIV()
      return new TLSCiphertext(new Uint8Array(output));
   }
   /**
    * 
    * @param {tlsCipherText} tlsCipherText 
    * @returns 
    */
   async decrypt(tlsCipherText) {
      await this.importKey();
      this.algo.additionalData = tlsCipherText.header;
      const output = await self.crypto.subtle.decrypt(this.algo, this.cryptoKey, tlsCipherText.encrypted_record);
      return new Uint8Array(output);
   }
}