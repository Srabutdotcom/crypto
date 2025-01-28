import { hkdfExtract256, hkdfExtract384 } from "../hkdf/hkdf.js";
import { derivedSecret, DerivedSecret, hkdfExpandLabel } from "../keyschedule/keyschedule.js";
import { TranscriptMsg } from "./transcript.js";
import { Enum } from "../dep.ts";
import { Aead } from "../aead/aead.js";

export class HandshakeRole extends Enum {
   static CLIENT = new HandshakeRole('CLIENT', 'CLIENT');
   static SERVER = new HandshakeRole('SERVER', 'SERVER')
}

export class FullHandshake {
   transcript = new TranscriptMsg;
   constructor(clientHello, serverHello, privateKey, role = HandshakeRole.CLIENT, _compare) {
      //TODO - validate arguments
      this.clientHello = clientHello;
      this.serverHello = serverHello;
      this.transcript.insert(clientHello.handshake, serverHello.handshake);
      this.cipher = serverHello.cipher_suite;
      switch (this.cipher.hashLength) {
         case 32: {
            this.derivedKey = DerivedSecret.SHA256;
            this.hkdfExtract = hkdfExtract256;
            break
         }
         case 48: {
            this.derivedKey = DerivedSecret.SHA384;
            this.hkdfExtract = hkdfExtract384;
            break
         }
      }
      this.namedGroup = serverHello.ext['KEY_SHARE'].group;
      this.role = role;
      this.privateKey = privateKey;

      const hs_key = this.hkdfExtract(this.derivedKey, this.sharedSecret);
      const c_hs_key = derivedSecret(hs_key, 'c hs traffic', this.transcript.byte);
      const s_hs_key = derivedSecret(hs_key, 's hs traffic', this.transcript.byte);
      
      const key_hs_s = hkdfExpandLabel(s_hs_key, "key", new Uint8Array, this.cipher.keyLength);
      const iv_hs_s = hkdfExpandLabel(s_hs_key, "iv", new Uint8Array, 12);
      this.aead_hs_s = new Aead(key_hs_s, iv_hs_s);

      const key_hs_c = hkdfExpandLabel(c_hs_key, "key", new Uint8Array, this.cipher.keyLength);
      const iv_hs_c = hkdfExpandLabel(c_hs_key, "iv", new Uint8Array, 12);
      this.aead_hs_c = new Aead(key_hs_c, iv_hs_c);

      this.finished_key_s ||= hkdfExpandLabel(s_hs_key, 'finished', new Uint8Array);
      this.finished_key_c ||= hkdfExpandLabel(c_hs_key, 'finished', new Uint8Array);

      const derivedMaster = derivedSecret(hs_key, 'derived');
      this.masterKey = this.hkdfExtract(derivedMaster)
   }
   get peerKey() {
      if (this.role == HandshakeRole.CLIENT) return this.serverHello.ext.KEY_SHARE.key_exchange;
      return this.clientHello.ext.get("KEY_SHARE").data.keyShareEntries.get(this.namedGroup)
   }
   get sharedSecret(){
      return this.namedGroup.keyGen.getSharedSecret(this.privateKey, this.peerKey)
   }
}