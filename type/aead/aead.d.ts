import { TLSCiphertext, TLSInnerPlaintext } from "../../src/dep.ts";

/**
 * Represents an AEAD (Authenticated Encryption with Associated Data) cipher, specifically AES-GCM.
 * Used for encrypting and decrypting TLS records in TLS 1.3.
 */
export declare class Aead {
  /**
   * Encryption sequence number (positive integer).
   */
  seqEnc: number;

  /**
   * Decryption sequence number (positive integer).
   */
  seqDec: number;

  /**
   * Encryption key.
   */
  key: Uint8Array;

  /**
   * Initialization vector (IV) for encryption.
   */
  ivEnc: Uint8Array;

  /**
   * Initialization vector (IV) for decryption.
   */
  ivDec: Uint8Array;

  /**
   * CryptoKey for AES-GCM encryption and decryption.
   */
  cryptoKey?: CryptoKey;

  /**
   * Creates an instance of the Aead class.
   * @param {Uint8Array} key - The encryption key.
   * @param {Uint8Array} iv - The initialization vector.
   */
  constructor(key: Uint8Array, iv: Uint8Array);

  /**
   * Builds the IV for encryption by incrementing the sequence number.
   */
  buildIVEnc(): void;

  /**
   * Builds the IV for decryption by incrementing the sequence number.
   */
  buildIVDec(): void;

  /**
   * Imports the encryption key into Web Crypto API for AES-GCM.
   * Ensures the key is imported only once.
   * @returns {Promise<void>}
   */
  importKey(): Promise<void>;

  /**
   * Encrypts the given TLSInnerPlaintext using AES-GCM.
   * @param {Uint8Array} content - The plaintext content.
   * @param {number} type - The content type.
   * @param {number} numZeros - The number of padding zeros.
   * @returns {Promise<TLSCiphertext>} The encrypted TLSCiphertext.
   */
  encrypt(
    content: Uint8Array,
    type: number,
    numZeros: number,
  ): Promise<TLSCiphertext>;

  /**
   * Decrypts the given TLSCiphertext using AES-GCM.
   * @param {TLSCiphertext | Uint8Array} tlsCipherText - The ciphertext to decrypt.
   * @returns {Promise<TLSInnerPlaintext>} The decrypted TLSInnerPlaintext.
   */
  decrypt(
    tlsCipherText: TLSCiphertext | Uint8Array,
  ): Promise<TLSInnerPlaintext>;

  /**
   * Encrypts the given content using the GCM implementation.
   * @param {Uint8Array} content - The plaintext content.
   * @param {number} type - The content type.
   * @param {number} numZeros - The number of padding zeros.
   * @returns {TLSCiphertext} The encrypted TLSCiphertext.
   */
  seal(content: Uint8Array, type: number, numZeros: number): TLSCiphertext;

  /**
   * Decrypts the given TLSCiphertext using the GCM implementation.
   * @param {TLSCiphertext | Uint8Array} tlsCipherText - The ciphertext to decrypt.
   * @returns {TLSInnerPlaintext} The decrypted TLSInnerPlaintext.
   */
  open(tlsCipherText: TLSCiphertext | Uint8Array): TLSInnerPlaintext;
}
