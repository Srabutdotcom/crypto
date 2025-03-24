import { Constrained, Struct } from "../../src/dep.ts";

/**
 * Derives a secret using the TLS 1.3 HKDF scheme.
 * @param secret - The input secret from which to derive the new secret.
 * @param label - A label indicating the purpose of the derived secret.
 * @param messages - Optional message data for context.
 * @returns The derived secret.
 */
export declare function derivedSecret(
  secret: Uint8Array,
  label: string,
  messages: Uint8Array,
  hashLength: 32 | 48,
): Uint8Array;

/**
 * Expands a secret using HKDF with a label and context.
 * @param secret - The input secret.
 * @param label - A label indicating the purpose of the expansion.
 * @param context - Context information.
 * @param Length - The output hash length (32, 48, or 64 bytes).
 * @returns The expanded key.
 */
export declare function hkdfExpandLabel(
  secret: Uint8Array,
  label: string,
  context: Uint8Array,
  Length: number,
): Uint8Array;

/**
 * Represents the HKDF label structure used in TLS 1.3.
 */
declare class HkdfLabel extends Struct {
  /**
   * Creates an HKDF label instance.
   * @param hashByteLength - The hash output length.
   * @param label - The label for the HKDF context.
   * @param context - The context information.
   * @returns An instance of the HKDF label.
   */
  static of(
    hashByteLength: Uint8Array | number,
    label: Uint8Array | number,
    context: Uint8Array | number,
  ): HkdfLabel;

  constructor(
    hashByteLength: Uint8Array | number,
    label: Uint8Array | number,
    context: Uint8Array | number,
  );
}

/**
 * Represents a constrained label for HKDF.
 */
declare class Label extends Constrained {
  /**
   * Creates a Label instance.
   * @param label - The label string.
   * @returns An instance of Label.
   */
  static of(label: Uint8Array | number): Label;

  constructor(label: Uint8Array | number);
}

/**
 * Represents a constrained context for HKDF.
 */
declare class Context extends Constrained {
  /**
   * Creates a Context instance.
   * @param context - The context data.
   * @returns An instance of Context.
   */
  static of(context: Uint8Array | number): Context;

  constructor(context: Uint8Array | number);
}

/**
 * Represents derived secrets for different hash functions in TLS 1.3.
 */
export class DerivedSecret {
  /**
   * The derived secret for SHA-256 (32 bytes).
   */
  static SHA256: Uint8Array;

  /**
   * The derived secret for SHA-384 (48 bytes).
   */
  static SHA384: Uint8Array;
}

/**
 * Derives the "finished" key in the TLS 1.3 handshake.
 *
 * @param {Uint8Array} serverHS_secret - The server handshake secret.
 * @param {number} [hashLength] - The length of the hash output (default is the length of the serverHS_secret).
 * @returns {Uint8Array} - The derived "finished" key.
 */
export function finishedKey(
  serverHS_secret: Uint8Array,
  hashLength?: number,
): Uint8Array;
