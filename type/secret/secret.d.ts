import { Aead } from "../../src/aead/aead.js";
import { TranscriptMsg } from "../../src/secret/transcript.js";
/**
 * Represents the cryptographic secrets used in a TLS handshake.
 */
export class Secret {
   keyLength: number;
   digestLength: number;
   namedGroup: any;
   derivedKey: any;
   sharedKey: Uint8Array | undefined;
   hsKey: Uint8Array | undefined;
   transcript: TranscriptMsg;
   masterKey: Uint8Array | undefined;
   hsTrafficKeyClient: Uint8Array | undefined;
   hsTrafficKeyServer: Uint8Array | undefined;
   keyHSServer: Uint8Array | undefined;
   ivHSServer: Uint8Array | undefined;
   keyHSClient: Uint8Array | undefined;
   ivHSClient: Uint8Array | undefined;
   finishedKeyServer: Uint8Array | undefined;
   finishedKeyClient: Uint8Array | undefined;
   aeadHSServer: Aead | undefined;
   aeadHSClient: Aead | undefined;
   apKeyClient: Uint8Array | undefined;
   apKeyServer: Uint8Array | undefined;
   expMaster: Uint8Array | undefined;
   resMaster: Uint8Array | undefined;
   resumption: Uint8Array | undefined;
   keyAPClient: Uint8Array | undefined;
   keyAPServer: Uint8Array | undefined;
   ivAPClient: Uint8Array | undefined;
   ivAPServer: Uint8Array | undefined;
   aeadAPServer: Aead | undefined;
   aeadAPClient: Aead | undefined;
 
   /**
    * Creates an instance of the `Secret` class.
    * @param cipher - The cipher suite being used.
    * @param namedGroup - The named group for key exchange.
    * @param privateKey - The private key (optional).
    * @param publicKey - The public key (optional).
    * @param peerPublicKey - The peer's public key (optional).
    */
   constructor(cipher: string, namedGroup: any, privateKey?: Uint8Array, publicKey?: Uint8Array, peerPublicKey?: Uint8Array);
 
   /**
    * Computes the handshake secret.
    * @param sharedKey - The shared key from the key exchange.
    * @returns The handshake secret as a `Uint8Array`.
    */
   getHSSecret(sharedKey: Uint8Array): Uint8Array;
 
   /**
    * Computes the shared secret from the peer's public key.
    * @param peerPublicKey - The peer's public key.
    * @returns The shared secret as a `Uint8Array`.
    */
   getSharedSecret(peerPublicKey: Uint8Array): Uint8Array;
 
   /**
    * Updates handshake keys using the provided client and server hello messages.
    * @param clientHelloMsg - The client hello message.
    * @param serverHelloMsg - The server hello message.
    */
   updateHSKey(clientHelloMsg: Uint8Array, serverHelloMsg: Uint8Array): void;
 
   /**
    * Computes the master key from the handshake secret.
    * @returns The master key as a `Uint8Array`.
    */
   getMasterKey(): Uint8Array;
 
   /**
    * Sets the private key for the named group.
    */
   set privateKey(key: Uint8Array);
 
   /**
    * Sets the public key for the named group.
    */
   set publicKey(key: Uint8Array);
 
   /**
    * Updates application keys using various TLS handshake messages.
    * @param encryptedExtMsg - The encrypted extensions message.
    * @param certificateMsg - The certificate message.
    * @param rsaPrivateKey - The RSA private key.
    * @param signaturescheme - The signature scheme used.
    * @param certificateVerifyMsg_0 - The certificate verify message (optional).
    * @param finishedMsg_0 - The finished message from the server (optional).
    * @param finishedClientMsg_0 - The finished message from the client (optional).
    */
   updateAPKey(
     encryptedExtMsg: Uint8Array,
     certificateMsg: Uint8Array,
     rsaPrivateKey: Uint8Array,
     signaturescheme: any,
     certificateVerifyMsg_0?: Uint8Array,
     finishedMsg_0?: Uint8Array,
     finishedClientMsg_0?: Uint8Array
   ): Promise<void>;
 
   /**
    * Computes the resumption secret.
    * @param ticketNonce - The ticket nonce.
    * @returns The resumption secret as a `Uint8Array`.
    */
   getResumption(ticketNonce?: Uint8Array): Uint8Array;
 }
 


