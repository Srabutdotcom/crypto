import { TLSInnerPlaintext, TLSCiphertext } from "../../src/dep.ts"
/**
 * Class representing an AES-GCM AEAD encryption/decryption handler.
 */
export class Aead {
   /**
    * Sequential number used for building IV.
    * @type {number}
    */
   seq: number;
 
   /**
    * Encryption key as a Uint8Array.
    * @type {Uint8Array}
    */
   key: Uint8Array;
 
   /**
    * Initialization vector (IV) as a Uint8Array.
    * @type {Uint8Array}
    */
   iv: Uint8Array;
 
   /**
    * AES-GCM algorithm configuration.
    * @type {{ name: "AES-GCM"; iv: Uint8Array; additionalData: Uint8Array; }}
    */
   algo: {
     name: "AES-GCM";
     iv: Uint8Array;
     additionalData: Uint8Array;
   };
 
   /**
    * CryptoKey instance for AES-GCM operations.
    * @type {CryptoKey}
    */
   cryptoKey: CryptoKey | undefined;
 
   /**
    * Constructs an Aead instance.
    *
    * @param {Uint8Array} key - Encryption key.
    * @param {Uint8Array} iv - Initialization vector (IV).
    */
   constructor(key: Uint8Array, iv: Uint8Array);
 
   /**
    * Builds the IV by XORing with the sequential number.
    */
   buildIV(): void;
 
   /**
    * Imports the encryption key as a CryptoKey.
    * Ensures the key is imported only once.
    * 
    * @returns {Promise<void>}
    */
   importKey(): Promise<void>;
 
   /**
    * Encrypts a `TLSInnerPlaintext` instance using AES-GCM.
    *
    * @param {TLSInnerPlaintext} tlsInnerPlaintext - Data to be encrypted.
    * @returns {Promise<TLSCiphertext>} A promise resolving to a `TLSCiphertext` instance.
    */
   encrypt(tlsInnerPlaintext: TLSInnerPlaintext): Promise<TLSCiphertext>;
 
   /**
    * Decrypts a `TLSCiphertext` instance using AES-GCM.
    *
    * @param {TLSCiphertext} tlsCipherText - Data to be decrypted.
    * @returns {Promise<Uint8Array>} A promise resolving to the decrypted data as a Uint8Array.
    */
   decrypt(tlsCipherText: TLSCiphertext): Promise<Uint8Array>;
 }
 