//@ts-self-types="../../type/aead/aead.d.ts"
import { TLSCiphertext,/* , Crypto */ 
TLSInnerPlaintext} from "../dep.ts"
import { AES } from "../dep.ts"
import { GCM } from "../dep.ts"

//const crypto = new Crypto();

export class Aead { //*AESGCM

   /**
    * @type {number} sequential number - positive integer
    */
   seqEnc = 0
   seqDec = 0

   /**
    * @type {Uint8Array} key - octet
    */
   key

   /**
    * @type {Uint8Array} iv - Uint8Array
    */
   ivEnc
   ivDec

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
      this.ivEnc = Uint8Array.from(iv);
      this.ivDec = Uint8Array.from(iv);
      this.gcm = new GCM(new AES(key));//const cipher = new AES(key.byte)
   }
   buildIVEnc() {
      this.seqEnc++;
      for (let i = 0; i < 8; i++) {
         this.ivEnc[this.ivEnc.length - 1 - i] ^= ((this.seqEnc >> (i * 8)) & 0xFF);
      }
   }
   buildIVDec() {
      this.seqDec++;
      for (let i = 0; i < 8; i++) {
         this.ivDec[this.ivDec.length - 1 - i] ^= ((this.seqDec >> (i * 8)) & 0xFF);
      }
   }
   async importKey() {
      if (this.cryptoKey) return
      this.cryptoKey = await crypto.subtle.importKey('raw', this.key, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'])
   }
   /**
    * 
    * @param {TLSInnerPlaintext} tlsInnerPlaintext - data to be encrypted in Uint8Array
    * @returns {TLSCiphertext}
    */
   async encrypt(tlsInnerPlaintext) {
      const _header = header(tlsInnerPlaintext, this.key.length);
      await this.importKey();
      const output = await crypto.subtle.encrypt({
         name: "AES-GCM",
         iv: this.ivEnc,
         additionalData: _header, // as additional data
         //tagLength: 128 //*by default is 128
      }, this.cryptoKey, tlsInnerPlaintext);
      this.buildIVEnc()
      return new TLSCiphertext(new Uint8Array(output));
   }
   /**
    * 
    * @param {tlsCipherText} tlsCipherText 
    * @returns 
    */
   async decrypt(tlsCipherText) {
      await this.importKey();
      const output = await crypto.subtle.decrypt({
         name: "AES-GCM",
         iv: this.ivDec,
         additionalData: tlsCipherText.header, // as additional data
         //tagLength: 128 //*by default is 128
      }, this.cryptoKey, tlsCipherText.encrypted_record);
      this.buildIVDec()
      return TLSInnerPlaintext.from(new Uint8Array(output));
   }

   seal(tlsInnerPlaintext){
      const _header = header(tlsInnerPlaintext, this.key.length);
      const sealed = this.gcm.seal(this.ivEnc, tlsInnerPlaintext, _header);
      this.buildIVEnc();
      return new TLSCiphertext(sealed);
   }

   open(tlsCipherText){
      const opened = this.gcm.open(this.ivDec, tlsCipherText.encrypted_record, tlsCipherText.header);
      this.buildIVDec();
      return TLSInnerPlaintext.from(opened);
   }

}

function header(tlsInnerPlaintext, keyLength){
   const lengthOf = tlsInnerPlaintext.length + keyLength;
   // header always 23 - application
   return Uint8Array.of(23, 3, 3, Math.trunc(lengthOf / 256), lengthOf % 256);
}