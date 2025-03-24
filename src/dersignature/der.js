//LINK https://github.com/libbitcoin/libbitcoin-system/wiki/ECDSA-and-DER-Signatures
//LINK https://www.rfc-editor.org/rfc/rfc3279#page-7

import { safeuint8array } from "../dep.ts";

/* 
30 - DER prefix
45 - Length of rest of Signature
02 - Marker for r value
21 - Length of r value
00ed...8f - r value, Big Endian
02 - Marker for s value
21 - Length of s value
7a98...ed - s value, Big Endian 
*/

export class DERSignature extends Uint8Array {
   static sanitize(arr) {
      if (arr.at(0) !== 0x30) throw Error(`Expected DER prefix 0x30`);
      const lengthOf = arr.at(1);
      const copy = arr.slice(0, 2 + lengthOf);
      return [copy]
   }
   static from(arr) { return new DERSignature(arr) }
   #r
   #s
   constructor(...args) {
      args = (args[0] instanceof Uint8Array) ? DERSignature.sanitize(args[0]) : args
      super(...args)
   }
   get r() {
      if (this.#r) return this.#r
      const end = 4 + this.at(3);
      // if the first byte is zero start in next 1 byte 
      this.#r ||= this.subarray(this.at(4) == 0 ? 5 : 4, end);
      this.#r.end = end;
      return this.#r
   }
   get s() {
      if (this.#s) return this.#s
      const start = this.#r.end + 2;
      const end = start + this.at(this.#r.end + 1);
      // https://bitcoin.stackexchange.com/questions/92680/what-are-the-der-signature-and-sec-format
      // if the first byte is zero start in next 1 byte 
      this.#s ||= this.subarray(this.at(start) == 0 ? start + 1 : start, end);
      this.#s.end = end;
      return this.#s
   }
   get rs() {
      return safeuint8array(this.r, this.s)
   }
}