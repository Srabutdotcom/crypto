//@ts-self-types="../../type/aead/aead.d.ts"
import {
   //TLSCiphertext,
   TLSInnerPlaintext
} from "../dep.ts"
import { AES } from "../dep.ts"
import { GCM } from "../dep.ts"

//const crypto = new Crypto();

export class Aead { //*AESGCM

   iv;
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
      this.iv = Uint8Array.from(iv)
      this.gcm = new GCM(new AES(key));//const cipher = new AES(key.byte)
   }

   async importKey() {
      if (this.cryptoKey) return
      this.cryptoKey = await crypto.subtle.importKey('raw', this.key, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'])
   }
   /**
    * 
    * @param {TLSInnerPlaintext} tlsInnerPlaintext - data to be encrypted in Uint8Array
    * @returns 
    */
   async encrypt(content, type, numZeros) {
      const tlsInnerPlaintext = TLSInnerPlaintext.fromContentTypeNumZeros(content, type, numZeros)
      await this.importKey();
      const aad = Uint8Array.of(23, 3, 3, 0, tlsInnerPlaintext.length + 16);
      const buffer = await crypto.subtle.encrypt({
         name: "AES-GCM",
         iv: this.seqEnc == 0 ? this.iv : ivXorSeqOpt(this.iv, this.seqEnc),
         additionalData: aad, // as additional data
         //tagLength: 128 //*by default is 128
      }, this.cryptoKey, tlsInnerPlaintext);
      this.seqEnc += 1;
      const tlsCipherText = new Uint8Array(aad.length + buffer.byteLength);
      tlsCipherText.set(aad, 0);
      tlsCipherText.set(new Uint8Array(buffer), aad.length)
      return tlsCipherText;
   }
   /**
    * 
    * @param {TLSCiphertext} tlsCipherText 
    * @returns 
    */
   async decrypt(tlsCipherText) {
      //tlsCipherText = (tlsCipherText instanceof TLSCiphertext)? tlsCipherText : TLSCiphertext.from(tlsCipherText)
      await this.importKey();

      const buffer = await crypto.subtle.decrypt({
         name: "AES-GCM",
         iv: this.seqDec == 0 ? this.iv : ivXorSeqOpt(this.iv, this.seqDec),
         additionalData: tlsCipherText.subarray(0, 5), // as additional data
         //tagLength: 128 //*by default is 128
      }, this.cryptoKey, tlsCipherText.subarray(5)); // encrypted_record
      this.seqDec += 1;
      return TLSInnerPlaintext.from(new Uint8Array(buffer));
   }

   seal(content, type, numZeros) {
      const tlsInnerPlaintext = TLSInnerPlaintext.fromContentTypeNumZeros(content, type, numZeros);
      const aad = Uint8Array.of(23, 3, 3, 0, tlsInnerPlaintext.length + 16);
      const sealed = this.gcm.seal(this.seqEnc == 0 ? this.iv : ivXorSeqOpt(this.iv, this.seqEnc), tlsInnerPlaintext, aad);
      this.seqEnc += 1;
      const tlsCipherText = new Uint8Array(aad.length + sealed.length);
      tlsCipherText.set(aad, 0);
      tlsCipherText.set(sealed, aad.length)
      return tlsCipherText;
   }

   open(tlsCipherText) {
      //tlsCipherText = (tlsCipherText instanceof TLSCiphertext) ? tlsCipherText : TLSCiphertext.from(tlsCipherText)
      const opened = this.gcm.open(this.seqDec == 0 ? this.iv : ivXorSeqOpt(this.iv, this.seqDec), tlsCipherText.subarray(5), tlsCipherText.subarray(0, 5));
      this.seqDec += 1;
      return TLSInnerPlaintext.from(opened);
   }

}

/**
 * 
 * {@link https://www.rfc-editor.org/rfc/rfc8446#section-5.3 | Per-Record Nonce }
 * 
 * The per-record nonce for the AEAD
   construction is formed as follows
   1.  The 64-bit record sequence number is encoded in network byte
       order and padded to the left with zeros to iv_length.
   2.  The padded sequence number is XORed with either the static
       client_write_iv or server_write_iv (depending on the role).
 * @param {Uint8Array} iv 12 bytes nonce 
 * @param {number} seq 
 * @returns 
 */
function _ivXorSeq(iv, seq) {
   const nonce = Uint8Array.from(iv);
   const buffer = new ArrayBuffer(8);
   const view = new DataView(buffer);
   const seqArr = new Uint8Array(buffer);
   view.setBigUint64(0, BigInt(seq));
   let i = 11;
   let j = 0n;
   let cons = BigInt(seq)
   while (true) {
      nonce[i] ^= seqArr[i - 4];
      cons -= BigInt(seqArr[i - 4]) * 256n ** j;
      if (cons == 0n) break;
      i -= 1; j += 1n
   }
   return nonce
}

export function ivXorSeqOpt(iv, seq) {
   const nonce = Uint8Array.from(iv);
   const seqArr = new Uint8Array(8);
   const view = new DataView(seqArr.buffer);
   view.setBigUint64(0, BigInt(seq));

   let i = 11;
   let seqVal = seq;

   while (seqVal > 0) {
      nonce[i] ^= seqArr[i - 4];
      seqVal = Math.floor(seqVal / 256);
      i--;
   }
   return nonce;
}
