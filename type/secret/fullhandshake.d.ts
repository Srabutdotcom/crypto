import { ClientHello, ServerHello } from "../../src/dep.ts";
import { Aead, DerivedSecret } from "../../src/mod.ts";
import { HandshakeRole } from "../../src/secret/fullhandshake.js";
import { TranscriptMsg } from "../../src/secret/transcript.js";

/**
 * Represents a full TLS 1.3 handshake implementation.
 */
export class FullHandshake {
   /**
    * The transcript of handshake messages.
    */
   transcript: TranscriptMsg;
 
   /**
    * The ClientHello message in the handshake.
    */
   clientHello: any;
 
   /**
    * The ServerHello message in the handshake.
    */
   serverHello: any;
 
   /**
    * The cipher suite used in the handshake.
    */
   cipher: any;
 
   /**
    * The derived key type based on the hash algorithm.
    */
   derivedKey: DerivedSecret;
 
   /**
    * Function to perform HKDF extraction based on the selected hash algorithm.
    */
   hkdfExtract: (salt: Uint8Array, ikm: Uint8Array) => Uint8Array;
 
   /**
    * The named group used for key exchange.
    */
   namedGroup: any;
 
   /**
    * The role in the handshake (CLIENT or SERVER).
    */
   role: HandshakeRole;
 
   /**
    * The private key of the participant in the handshake.
    */
   privateKey: any;
 
   /**
    * The AEAD instance for server-side handshake encryption.
    */
   aead_hs_s: Aead;
 
   /**
    * The AEAD instance for client-side handshake encryption.
    */
   aead_hs_c: Aead;
 
   /**
    * The finished key for the server.
    */
   finished_key_s: Uint8Array;
 
   /**
    * The finished key for the client.
    */
   finished_key_c: Uint8Array;
 
   /**
    * The master secret key derived during the handshake.
    */
   masterKey: Uint8Array;
 
   /**
    * Constructs a FullHandshake instance.
    * 
    * @param clientHello - The ClientHello message.
    * @param serverHello - The ServerHello message.
    * @param privateKey - The private key of the participant.
    * @param role - The handshake role (default is CLIENT).
    * @param compare - Optional function for comparison operations.
    */
   constructor(
     clientHello: ClientHello,
     serverHello: ServerHello,
     privateKey: Uint8Array,
     role?: HandshakeRole,
     //compare?: (a: any, b: any) => boolean
   );
 
   /**
    * Computes the peer's public key based on the role.
    */
   get peerKey(): Uint8Array;
 
   /**
    * Computes the shared secret for the handshake.
    */
   get sharedSecret(): Uint8Array;
 }
 