import { Aead } from "../../src/aead/aead.js";
import { NamedGroup } from "../../src/dep.ts";
/**
 * Represents the derived secrets used in the TLS handshake process.
 */
export class Secret {
   /**
    * Length of the cryptographic key in bytes.
    */
   keyLength: number;

   /**
    * Length of the hash digest in bytes.
    */
   digestLength: number;

   /**
    * The named group used in the key exchange (e.g., P-256, P-384).
    */
   namedGroup: NamedGroup;

   /**
    * The derived key based on the hash function.
    */
   derivedKey: Uint8Array;

   /**
    * The shared secret generated during the key exchange.
    */
   sharedKey?: Uint8Array;

   /**
    * The handshake secret derived from the shared key.
    */
   handshakeKey?: Uint8Array;

   /**
    * Combined client and server messages for transcript hash calculation.
    */
   transcriptMsg?: any;

   /**
    * The master secret derived during the handshake process.
    */
   masterKey?: Uint8Array;

   /**
    * The AEAD writer instance for secure communication.
    */
   aeadWriter?: Aead;

   /**
    * The AEAD reader instance for secure communication.
    */
   aeadReader?: Aead;

   /**
    * Creates a new Secret instance.
    * @param cipher The cipher suite used (e.g., 'AES_256_GCM_SHA384').
    * @param namedGroup The named group used in key exchange.
    * @param peerPublicKey The public key of the peer (optional).
    */
   constructor(
      cipher: string,
      namedGroup: NamedGroup,
      privateKey?: Uint8Array,
      publicKey?: Uint8Array,
      peerPublicKey?: Uint8Array,
   );

   /**
    * Derives the handshake secret using the shared key.
    * @param sharedKey The shared secret.
    * @returns The handshake secret.
    */
   getHandshakeSecret(sharedKey: Uint8Array): Uint8Array;

   /**
    * Derives the shared secret using the peer's public key.
    * @param peerPublicKey The public key of the peer.
    * @returns The shared secret.
    */
   getSharedSecret(peerPublicKey: Uint8Array): Uint8Array;

   /**
    * Derives the client handshake traffic key.
    * @param clientHelloMsg The client's hello message.
    * @param serverHelloMsg The server's hello message.
    * @returns The client handshake traffic key.
    */
   getClientHandShakeTrafficKey(
      clientHelloMsg: Uint8Array,
      serverHelloMsg: Uint8Array,
   ): Uint8Array;

   /**
    * Derives the server handshake traffic key.
    * @param clientHelloMsg The client's hello message.
    * @param serverHelloMsg The server's hello message.
    * @returns The server handshake traffic key.
    */
   getServerHandShakeTrafficKey(
      clientHelloMsg: Uint8Array,
      serverHelloMsg: Uint8Array,
   ): Uint8Array;

   /**
    * Derives the master key from the handshake key.
    * @returns The master key.
    */
   getMasterKey(): Uint8Array;

   /**
    * Derives the server's handshake key and IV.
    */
   getHandshakeServerKeyNonce(): void;

   /**
    * Derives the client's handshake key and IV.
    */
   getHandshakeClientKeyNonce(): void;

   /**
    * Derives the finished server key.
    * @returns The finished server key.
    */
   getFinishedServerKey(): Uint8Array;

   /**
    * Derives the finished client key.
    * @returns The finished client key.
    */
   getFinishedClientKey(): Uint8Array;

   /**
    * Sets privateKey to this secret class
    */
   set privateKey(key: Uint8Array);

   /**
    * Sets publicKey to this secret class
    */
   set publicKey(key: Uint8Array);
}
