import { Finished } from "../../src/dep.ts";
/**
 * Generates a `Finished` instance based on the provided finish key, message, and hash function.
 * 
 * @param finish_key - The key used to finish the operation.
 * @param message - The message to be processed.
 * @param sha - The hash function identifier, either `256` for SHA-256 or `384` for SHA-384.
 * @returns A new `Finished` instance based on the processed data.
 */
declare function finished(
   finish_key: Uint8Array,
   message: Uint8Array,
   sha: 256 | 384
 ): Finished;