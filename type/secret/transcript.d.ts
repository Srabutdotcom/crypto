import { HandshakeType, Handshake } from "../../src/dep.ts";

/**
 * Represents a collection of handshake messages, extending Set.
 * Provides additional utilities for inserting and retrieving handshake messages.
 */
export class TranscriptMsg extends Set<Uint8Array> {
   /**
    * Internal map to store messages by their handshake type.
    */
   #msgMap: Map<HandshakeType, Uint8Array>;

   /**
    * Constructs a new TranscriptMsg instance.
    * @param msgs - An array of Uint8Array messages to initialize the set.
    */
   constructor(...msgs: Uint8Array[]);

   /**
    * Inserts messages into the transcript.
    * Each message is mapped based on its handshake type.
    * @param msgs - One or more Uint8Array messages to insert.
    */
   insert(...msgs: Uint8Array[]): void;

   /**
    * Returns a Uint8Array representing all stored messages.
    */
   get byte(): Uint8Array;

   /**
    * Retrieves a handshake message by its type.
    * @param type - The handshake type identifier.
    * @returns The corresponding handshake message or undefined if not found.
    */
   getHandshake(type: HandshakeType): Uint8Array | undefined;
}

/**
 * Represents the TLS 1.3 handshake transcript.
 */
export class Transcript {
   /** Internal storage of handshake messages. */
   #handshakes: Uint8Array[];
   
   /** The message hash (if HelloRetryRequest is used). */
   #message_hash: Uint8Array | null;
   
   /** The HelloRetryRequest message, if present. */
   #helloRetryRequestMsg: Uint8Array | null;
   
   /** The first ClientHello message. */
   #clientHelloMsg: Uint8Array | null;
   
   /** The ServerHello message. */
   #serverHelloMsg: Uint8Array | null;
   
   /** The EncryptedExtensions message. */
   #encryptExtsMsg: Uint8Array | null;
   
   /** The Certificate message. */
   #certificateMsg: Uint8Array | null;
   
   /** The CertificateVerify message. */
   #certificateVerifyMsg: Uint8Array | null;
   
   /** The Finished message. */
   #finishedMsg: Uint8Array | null;

   /**
    * Creates a new Transcript instance.
    * @param {Uint8Array[]} handshakes - Initial handshake messages.
    */
   constructor(...handshakes: Uint8Array[]);

   /**
    * Inserts multiple handshake messages into the transcript.
    * @param {Uint8Array[]} handshakes - The handshake messages to insert.
    */
   insertMany(...handshakes: Uint8Array[]): void;

   /**
    * Inserts a single handshake message into the transcript.
    * @param {Uint8Array} handshake - The handshake message to insert.
    * @throws {Error} If the first message is not ClientHello.
    */
   insert(handshake: Uint8Array): void;

   /**
    * Returns the concatenated byte representation of all handshake messages.
    * @returns {Uint8Array} The handshake transcript bytes.
    */
   get byte(): Uint8Array;

   /**
    * Returns the message hash (used when HelloRetryRequest is present).
    * @returns {Uint8Array | null} The message hash, or null if not applicable.
    */
   get messageHash(): Uint8Array | null;

   /**
    * Returns the HelloRetryRequest message.
    * @returns {Uint8Array | null} The HelloRetryRequest message, or null if not present.
    */
   get helloRetryRequestMsg(): Uint8Array | null;

   /**
    * Returns the first ClientHello message.
    * @returns {Uint8Array | null} The ClientHello message.
    */
   get clientHelloMsg(): Uint8Array | null;

   /**
    * Returns the ServerHello message.
    * @returns {Uint8Array | null} The ServerHello message.
    */
   get serverHelloMsg(): Uint8Array | null;

   /**
    * Returns the EncryptedExtensions message.
    * @returns {Uint8Array | null} The EncryptedExtensions message.
    */
   get encryptedExtensionsMsg(): Uint8Array | null;

   /**
    * Returns the Certificate message.
    * @returns {Uint8Array | null} The Certificate message.
    */
   get certificateMsg(): Uint8Array | null;

   /**
    * Returns the CertificateVerify message.
    * @returns {Uint8Array | null} The CertificateVerify message.
    */
   get certificateVerifyMsg(): Uint8Array | null;

   /**
    * Returns the Finished message.
    * @returns {Uint8Array | null} The Finished message.
    */
   get finishedMsg(): Uint8Array | null;
}

