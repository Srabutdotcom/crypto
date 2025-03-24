import { hkdfExtract256, hkdfExtract384 } from "../hkdf/hkdf.js";
import { derivedSecret, DerivedSecret, hkdfExpandLabel } from "../keyschedule/keyschedule.js";

import { Enum, ExtensionType, parseItems, TLSPlaintext, hkdf } from "../dep.ts";

import { Aead } from "../aead/aead.js";
import { Transcript } from "./transcript.js";

export class HandshakeRole extends Enum {
   static CLIENT = new HandshakeRole('CLIENT', 'CLIENT');
   static SERVER = new HandshakeRole('SERVER', 'SERVER')
}

export class HandshakeKey {
   transcript 
   constructor(transcript, _compare) {
      //TODO - validate arguments
      
      this.transcript = transcript
      //this.transcript.insert(clientHello.handshake, serverHello.handshake);

      //FIXME - this handshake is not consistance need to revise to be able to access message properly 
      this.clientHello = this.transcript.clientHelloMsg.message;
      this.serverHello = this.transcript.serverHelloMsg.message;

      console.dir(`%cclientHello :\r\n`, "color: green", this.clientHello)
      console.dir(`%cserverHello :\r\n`, "color: green", this.serverHello)

      this.cipher = this.serverHello.cipher; console.log(`%ccipher :\r\n`, "color: green", this.cipher)
      // NOTE - consider to change this.derivedKey
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
      this.namedGroup = this.serverHello.extensions.get(ExtensionType.KEY_SHARE).data.group;
      this.role = this.clientHello.groups ? HandshakeRole.CLIENT : HandshakeRole.SERVER;
      this.init();
      console.log(`%cnamedGroup :\r\n`, "color: green", this.namedGroup);
      console.log(`%crole :\r\n`, "color: green", this.role);
   }
   init() {
      this.sharedSecret = this.getSharedSecret();
      //const hs_key = this.hkdfExtract(this.derivedKey, this.sharedSecret);
      const hs_key = hkdf.extract(this.cipher.hash, this.sharedSecret, this.derivedKey)
      console.log(`%chandshakeKey :\r\n`, "color: green", hs_key);
      
      const c_hs_key = derivedSecret(hs_key, 'c hs traffic', this.transcript.byte, this.cipher.hashLength);
      const s_hs_key = derivedSecret(hs_key, 's hs traffic', this.transcript.byte, this.cipher.hashLength);

      const key_hs_s = hkdfExpandLabel(s_hs_key, "key", new Uint8Array, this.cipher.keyLength);
      const iv_hs_s = hkdfExpandLabel(s_hs_key, "iv", new Uint8Array, 12);
      this.aead_hs_s = new Aead(key_hs_s, iv_hs_s);

      const key_hs_c = hkdfExpandLabel(c_hs_key, "key", new Uint8Array, this.cipher.keyLength);
      const iv_hs_c = hkdfExpandLabel(c_hs_key, "iv", new Uint8Array, 12);
      this.aead_hs_c = new Aead(key_hs_c, iv_hs_c);

      this.finished_key_s ||= hkdfExpandLabel(s_hs_key, 'finished', new Uint8Array, this.cipher.hashLength);
      this.finished_key_c ||= hkdfExpandLabel(c_hs_key, 'finished', new Uint8Array, this.cipher.hashLength);

      const derivedMaster = derivedSecret(hs_key, 'derived', new Uint8Array, this.cipher.hashLength);
      //this.masterKey = this.hkdfExtract(derivedMaster)
      this.masterKey = hkdf.extract(this.cipher.hash, new Uint8Array(this.cipher.hashLength), derivedMaster)
   }
   get peerKey() {
      let publicKey
      if (this.role == HandshakeRole.CLIENT) {
         const { _group, key_exchange } = this.serverHello.extensions.get(ExtensionType.KEY_SHARE).data;
         publicKey = key_exchange;
      } else {
         //NOTE - should be checked 
         publicKey = this.clientHello.extensions.get(ExtensionType.KEY_SHARE).data.keyShareEntries.get(this.namedGroup)
      }
      console.log(`%cpublicKey :\r\n`, "color: green", publicKey);
      return publicKey
   }
   getSharedSecret() {
      const privateKey = (this.role == HandshakeRole.CLIENT) ? this.clientHello.groups.get(this.namedGroup).privateKey : this.serverHello.group.get(this.namedGroup).privateKey; // FIXME to get private key from serverHello
      const shared = this.namedGroup.keyGen.getSharedSecret(privateKey, this.peerKey);
      if(shared.length==49)return shared.slice(1)
      if(shared.length==33)return shared.slice(1)
      console.log(`%cprivateKey :\r\n`, "color: green", privateKey);
      console.log(`%csharedKey :\r\n`, "color: green", shared);
      return shared
   }
}

export function parseRecords(array) {
   const records = parseItems(array, 0, array.length, TLSPlaintext)//new Set
   const output = new Map;
   for (const item of records) {
      output.set(item.type, item);
   }
   return output;
}

export class ApplicationKey {
   transcript
   masterKey
   cipher
   role
   finished_key_s
   finished_key_c
   exporter_master_secret
   finished_client
   constructor(handshakeKey, transcript = Transcript, _compare) {
      this.masterKey = handshakeKey.masterKey;
      this.cipher = handshakeKey.cipher; console.log(this.cipher.name)
      this.role = handshakeKey.role;
      this.transcript = transcript;
      this.finished_key_s = handshakeKey.finished_key_s
      this.finished_key_c = handshakeKey.finished_key_c
      
      const c_ap_traffic = derivedSecret(this.masterKey, "c ap traffic", this.transcript.byte, this.cipher.hashLength);
      const s_ap_traffic = derivedSecret(this.masterKey, "s ap traffic", this.transcript.byte, this.cipher.hashLength);
      this.exporter_master_secret ||= derivedSecret(this.masterKey, "exp master", this.transcript.byte, this.cipher.hashLength);
      const key_server = hkdfExpandLabel(s_ap_traffic, "key", new Uint8Array, this.cipher.keyLength);
      const iv_server = hkdfExpandLabel(s_ap_traffic, "iv", new Uint8Array, 12);
      const key_client = hkdfExpandLabel(c_ap_traffic, "key", new Uint8Array, this.cipher.keyLength);
      const iv_client = hkdfExpandLabel(c_ap_traffic, "iv", new Uint8Array, 12);
      this.aead_client ||= new Aead(key_client, iv_client);
      this.aead_server ||= new Aead(key_server, iv_server);

   }
   /* async finishedClient() {
      // create finished for client
      this.finished_client ||= await finished(this.finished_key_s, this.transcript.byte, this.cipher.hashLength * 8);
      const finishedClientMsg = Handshake.fromFinished(this.finished_client);

      this.transcript.insert(finishedClientMsg);

      this.res_master ||= derivedSecret(this.masterKey, "res master", this.transcript.byte, this.cipher.hashLength);
      return finishedClientMsg;
   } */
   resumption(ticketNonce = Uint8Array.of(0, 0)) {
      this.resumption ||= hkdfExpandLabel(this.res_master, 'resumption', ticketNonce, this.cipher.hashLength);
   }
}

