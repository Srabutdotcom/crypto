import { TLSInnerPlaintext, TLSCiphertext } from "../../src/dep.ts"

/**
 * Represents an AEAD (Authenticated Encryption with Associated Data) using AES-GCM.
 */
export class Aead {
  /**
   * Sequential number for encryption.
   * @type {number}
   */
  seqEnc: number;

  /**
   * Sequential number for decryption.
   * @type {number}
   */
  seqDec: number;

  /**
   * Encryption/Decryption key.
   * @type {Uint8Array}
   */
  key: Uint8Array;

  /**
   * Initialization vector for encryption.
   * @type {Uint8Array}
   */
  ivEnc: Uint8Array;

  /**
   * Initialization vector for decryption.
   * @type {Uint8Array}
   */
  ivDec: Uint8Array;

  /**
   * CryptoKey for AES-GCM operations.
   * @type {CryptoKey}
   */
  cryptoKey: CryptoKey;

  /**
   * Creates an instance of the `Aead` class.
   * @param {Uint8Array} key - The encryption/decryption key.
   * @param {Uint8Array} iv - The initialization vector.
   */
  constructor(key: Uint8Array, iv: Uint8Array);

  /**
   * Builds the next encryption initialization vector.
   */
  buildIVEnc(): void;

  /**
   * Builds the next decryption initialization vector.
   */
  buildIVDec(): void;

  /**
   * Imports the AES-GCM key for cryptographic operations.
   */
  importKey(): Promise<void>;

  /**
   * Encrypts the given plaintext using AES-GCM.
   * @param {TLSInnerPlaintext} tlsInnerPlaintext - The plaintext data to encrypt.
   * @returns {Promise<TLSCiphertext>} The encrypted ciphertext.
   */
  encrypt(tlsInnerPlaintext: TLSInnerPlaintext): Promise<TLSCiphertext>;

  /**
   * Decrypts the given ciphertext using AES-GCM.
   * @param {TLSCiphertext} tlsCipherText - The ciphertext to decrypt.
   * @returns {Promise<TLSInnerPlaintext>} The decrypted plaintext.
   */
  decrypt(tlsCipherText: TLSCiphertext): Promise<TLSInnerPlaintext>;

  /**
   * Encrypts the given plaintext using a custom AES-GCM implementation.
   * @param {TLSInnerPlaintext} tlsInnerPlaintext - The plaintext data to encrypt.
   * @returns {TLSCiphertext} The encrypted ciphertext.
   */
  seal(tlsInnerPlaintext: TLSInnerPlaintext): TLSCiphertext;

  /**
   * Decrypts the given ciphertext using a custom AES-GCM implementation.
   * @param {TLSCiphertext} tlsCipherText - The ciphertext to decrypt.
   * @returns {TLSInnerPlaintext} The decrypted plaintext.
   */
  open(tlsCipherText: TLSCiphertext): TLSInnerPlaintext;

  /**
   * Encrypts the given plaintext using AES-SIV (Synthetic Initialization Vector).
   * @param {TLSInnerPlaintext} tlsInnerPlaintext - The plaintext data to encrypt.
   * @returns {TLSCiphertext} The encrypted ciphertext.
   */
  sivSeal(tlsInnerPlaintext: TLSInnerPlaintext): TLSCiphertext;

  /**
   * Decrypts the given ciphertext using AES-SIV.
   * @param {TLSCiphertext} tlsCipherText - The ciphertext to decrypt.
   * @returns {TLSInnerPlaintext} The decrypted plaintext.
   */
  sivOpen(tlsCipherText: TLSCiphertext): TLSInnerPlaintext;
}

/**
* Generates a header for the AEAD encryption process.
* @param {TLSInnerPlaintext} tlsInnerPlaintext - The plaintext data to encrypt.
* @param {number} keyLength - The length of the encryption key.
* @returns {Uint8Array} The generated header.
*/
export function header(tlsInnerPlaintext: TLSInnerPlaintext, keyLength: number): Uint8Array;
