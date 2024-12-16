//@ts-self-types="../../type/secret/secret.d.ts"
import { DerivedSecret } from "../keyschedule/keyschedule.js";
import { hkdfExtract256, hkdfExtract384 } from "../hkdf/hkdf.js";
import { derivedSecret } from "../keyschedule/keyschedule.js";
import { hkdfExpandLabel } from "../keyschedule/keyschedule.js";
import { Aead } from "../aead/aead.js"
import { Struct } from "../dep.ts";

export class Secret {
   keyLength;
   digestLength;
   namedGroup;
   derivedKey;
   sharedKey;
   handshakeKey;
   transcriptMsg;
   masterKey;
   aeadWriter;
   aeadReader;
   constructor(cipher, namedGroup, privateKey, publicKey, peerPublicKey) {
      switch (cipher) {
         case 'AES_256_GCM_SHA384': {
            this.keyLength = 32;
            this.digestLength = 48; break
         }
         case 'CHACHA20_POLY1305_SHA256': {
            this.keyLength = 32;
            this.digestLength = 32; break
         }
         case 'AES_128_GCM_SHA256':
         default: {
            this.keyLength = 16;
            this.digestLength = 32; break
         }
      }
      this.namedGroup = namedGroup
      this.derivedKey = this.digestLength == 32 ? DerivedSecret.SHA256 : this.digestLength == 48 ? DerivedSecret.SHA384 : DerivedSecret.SHA256
      this.hkdfExtract = this.digestLength == 32 ? hkdfExtract256 : this.digestLength == 48 ? hkdfExtract384 : hkdfExtract256;
      if (privateKey) this.privateKey = privateKey
      if (publicKey) this.publicKey = publicKey
      if (peerPublicKey) {
         this.getSharedSecret(peerPublicKey)
         this.getHandshakeSecret(this.sharedKey)
      }
   }
   getHandshakeSecret(sharedKey) {
      if (this.handshakeKey) return this.handshakeKey;
      this.handshakeKey = this.hkdfExtract(this.derivedKey, sharedKey);
      return this.handshakeKey;
   }
   getSharedSecret(peerPublicKey) {
      if (this.sharedKey) return this.sharedKey;
      this.sharedKey = this.namedGroup.getSharedKey(peerPublicKey);
      return this.sharedKey;
   }
   getClientHandShakeTrafficKey(clientHelloMsg, serverHelloMsg) {
      if (!this.transcriptMsg) {
         this.transcriptMsg = Struct.createFrom(clientHelloMsg, serverHelloMsg)
      }
      this.clientHandshakeTrafficKey = derivedSecret(this.handshakeKey, 'c hs traffic', this.transcriptMsg.byte)
      return this.clientHandshakeTrafficKey
   }
   getServerHandShakeTrafficKey(clientHelloMsg, serverHelloMsg) {
      if (!this.transcriptMsg) {
         this.transcriptMsg = Struct.createFrom(clientHelloMsg, serverHelloMsg)
      }
      this.serverHandshakeTrafficKey = derivedSecret(this.handshakeKey, 's hs traffic', this.transcriptMsg.byte);
      return this.serverHandshakeTrafficKey;
   }
   getMasterKey() {
      if (!this.derivedMasterKey) {
         this.derivedMasterKey = derivedSecret(this.handshakeKey, 'derived')
      }
      this.masterKey = this.hkdfExtract(this.derivedMasterKey);
      return this.masterKey;
   }
   getHandshakeServerKeyNonce() {
      this.handshakeServerKey = hkdfExpandLabel(this.serverHandshakeTrafficKey, "key", new Uint8Array, this.keyLength);
      this.handshakeServerIV = hkdfExpandLabel(this.serverHandshakeTrafficKey, "iv", new Uint8Array, 12);
      this.aeadServer = new Aead(this.handshakeServerKey, this.handshakeServerIV);
   }
   getHandshakeClientKeyNonce() {
      this.handshakeClientKey = hkdfExpandLabel(this.clientHandshakeTrafficKey, "key", new Uint8Array, this.keyLength);
      this.handshakeClientIV = hkdfExpandLabel(this.clientHandshakeTrafficKey, "iv", new Uint8Array, 12);
      this.aeadClient = new Aead(this.handshakeClientKey, this.handshakeClientIV);
   }
   getFinishedServerKey() {
      return hkdfExpandLabel(this.serverHandshakeTrafficKey, 'finished', new Uint8Array);
   }
   getFinishedClientKey() {
      return hkdfExpandLabel(this.clientHandshakeTrafficKey, 'finished', new Uint8Array);
   }
   set privateKey(key) { this.namedGroup.privateKey = key };
   set publicKey(key) { this.namedGroup.publicKey = key };
}