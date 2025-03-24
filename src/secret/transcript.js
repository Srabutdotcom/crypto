//@ts-self-types="../../type/secret/transcript.d.ts"
import { HandshakeType, safeuint8array } from "../dep.ts";

export class TranscriptMsg extends Set {
   //items = new Set
   #msgMap = new Map;
   constructor(...msgs) {
      super([...msgs])
      for (const msg of this.values()) {
         this.#msgMap.set(HandshakeType.fromValue(msg.at(0)), msg)
      }
   }
   insert(...msgs) {
      for (const msg of msgs) {
         const type = msg.at(0);
         this.add(msg);
         this.#msgMap.set(HandshakeType.fromValue(type), msg)
      }
   }

   get byte() {
      return safeuint8array(...this.values())
   }

   getHandshake(type) {
      return this.#msgMap.get(type)
   }
}

export class Transcript {
   #handshakes = []
   #message_hash = null;
   #helloRetryRequestMsg = null;
   #clientHelloMsg = null;
   #serverHelloMsg = null;
   #encryptExtsMsg = null;
   #certificateMsg = null;
   #certificateVerifyMsg = null;
   #finishedMsg_1 = null;
   #finishedMsg_2 = null;

   constructor(...handshakes) {
      for (const handshake of handshakes) {
         this.insert(handshake)
      }
   }
   insertMany(...handshakes) {
      for (const handshake of handshakes) {
         this.insert(handshake)
      }
   }
   insert(handshake) {
      if (!this.#handshakes.length) {
         if (HandshakeType.fromValue(handshake[0]) !== HandshakeType.CLIENT_HELLO) throw Error(`Expected ClientHello`);
         this.#clientHelloMsg = handshake;
         this.#handshakes.push(handshake)
         return
      }
      if (handshake.isHRR) {
         const hash = handshake?.message?.cipher?.hash ?? Cipher.from(handshake.subarray(39 + handshake.at(38))).hash
         const hashClientHello1 = hash.create().update(this.#handshakes[0]).digest();
         this.#handshakes[0] = safeuint8array(
            HandshakeType.MESSAGE_HASH.byte,
            Uint8Array.of(0, 0, hashClientHello1.length),
            hashClientHello1
         )
         this.#handshakes.push(handshake)
         this.#message_hash = this.#handshakes.at(0);
         this.#helloRetryRequestMsg = this.#handshakes.at(1);
         return
      }
      switch (handshake?.type ?? HandshakeType.from(handshake)) {
         case HandshakeType.SERVER_HELLO:
            this.#serverHelloMsg = handshake; console.log('serverHelloMsg received')
            break;
         case HandshakeType.CLIENT_HELLO:
            this.#clientHelloMsg = handshake; console.log('clientHelloMsg received')
            break;
         case HandshakeType.ENCRYPTED_EXTENSIONS:
            this.#encryptExtsMsg = handshake; console.log('encryptExtsMsg received')
            break;
         case HandshakeType.CERTIFICATE:
            this.#certificateMsg = handshake; console.log('certificateMsg received')
            break;
         case HandshakeType.CERTIFICATE_VERIFY:
            this.#certificateVerifyMsg = handshake; console.log('certificateVerifyMsg received')
            break;
         case HandshakeType.FINISHED:
            if (!this.#finishedMsg_1) {
               this.#finishedMsg_1 = handshake; console.log('finishedMsg_1 received')
            } else {
               this.#finishedMsg_2 = handshake; console.log('finishedMsg_2 received')
            }
            break;
         default:
            console.log('other received');
            break;
      }
      this.#handshakes.push(handshake);
   }
   get byte() {
      return safeuint8array(...this.#handshakes)
   }
   get messageHash() {
      return this.#message_hash;
   }
   get helloRetryRequestMsg() {
      return this.#helloRetryRequestMsg;
   }
   get clientHelloMsg() {
      return this.#clientHelloMsg
   }
   get serverHelloMsg() {
      return this.#serverHelloMsg
   }
   get encryptedExtensionsMsg() {
      return this.#encryptExtsMsg
   }
   get certificateMsg() {
      return this.#certificateMsg
   }
   get certificateVerifyMsg() {
      return this.#certificateVerifyMsg
   }
   get finishedMsg_1() {
      return this.#finishedMsg_1;
   }
   get finishedMsg_2() {
      return this.#finishedMsg_2;
   }
}


