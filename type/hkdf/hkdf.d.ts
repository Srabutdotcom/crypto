/**
 * Computes the HKDF Extract step using the provided inputs.
 * @param hashBitLength - The bit length of the hash function (default: 256).
 * @param ikm - The input key material. Defaults to an empty `Uint8Array` of size `hashBitLength / 8`.
 * @param salt - The salt value. Defaults to an empty `Uint8Array` of size `hashBitLength / 8`.
 * @returns A `Promise` resolving to a `Uint8Array` containing the extracted pseudorandom key.
 */
export function hkdfExtract(
   hashBitLength?: number,
   ikm?: Uint8Array,
   salt?: Uint8Array,
): Promise<Uint8Array>;

/**
 * Computes the HKDF Extract step with SHA-256 as the hash function.
 * @param ikm - The input key material. Defaults to a `Uint8Array` of 32 bytes.
 * @param salt - The salt value. Defaults to an empty `Uint8Array`.
 * @returns A `Promise` resolving to a `Uint8Array` containing the extracted pseudorandom key.
 */
export function hkdfExtract256(
   ikm?: Uint8Array,
   salt?: Uint8Array,
): Promise<Uint8Array>;

/**
 * Computes the HKDF Extract step with SHA-384 as the hash function.
 * @param ikm - The input key material. Defaults to a `Uint8Array` of 48 bytes.
 * @param salt - The salt value. Defaults to an empty `Uint8Array`.
 * @returns A `Promise` resolving to a `Uint8Array` containing the extracted pseudorandom key.
 */
export function hkdfExtract384(
   ikm?: Uint8Array,
   salt?: Uint8Array,
): Promise<Uint8Array>;

/**
 * Computes the HKDF Extract step with SHA-512 as the hash function.
 * @param ikm - The input key material. Defaults to a `Uint8Array` of 64 bytes.
 * @param salt - The salt value. Defaults to an empty `Uint8Array`.
 * @returns A `Promise` resolving to a `Uint8Array` containing the extracted pseudorandom key.
 */
export function hkdfExtract512(
   ikm?: Uint8Array,
   salt?: Uint8Array,
): Promise<Uint8Array>;

/**
 * Represents an Early Secret for a specific hash function.
 */
export class EarlySecret {
   /**
    * The Early Secret for SHA-512.
    */
   static SHA512: EarlySecret;

   /**
    * The Early Secret for SHA-384.
    */
   static SHA384: EarlySecret;

   /**
    * The Early Secret for SHA-256.
    */
   static SHA256: EarlySecret;

   /**
    * Creates a new `EarlySecret` instance.
    * @param name - The name of the Early Secret (e.g., "SHA512").
    * @param value - The `Uint8Array` representing the Early Secret value.
    */
   constructor(name: string, value: Uint8Array);
}

/**
 * Expands a pseudorandom key (PRK) into a key of the desired length using the HKDF algorithm.
 * 
 * @param prk - The pseudorandom key obtained from the HKDF extract phase.
 * @param info - Context and application-specific information (can be empty).
 * @param hashByteLength - Desired length of the output key material (OKM) in bytes.
 * @returns A promise that resolves to the expanded key material.
 * 
 * @throws Error If the desired hashByteLength is invalid or the operation fails.
 */
export declare function hkdfExpand(
   prk: Uint8Array,
   info: Uint8Array,
   hashByteLength: number
): Promise<Uint8Array>;
