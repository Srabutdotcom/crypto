import { hkdfExtract256, hkdfExtract384 } from "../hkdf/hkdf.js";
import { derivedSecret, DerivedSecret, hkdfExpandLabel } from "../keyschedule/keyschedule.js";
import { TranscriptMsg } from "./transcript.js";
import { ClientHello, Enum, ExtensionType, parseItems, TLSPlaintext, Handshake } from "../dep.ts";
import { verifyCertificateVerify } from "../dep.ts"
import { Aead } from "../aead/aead.js";
import { finished } from "../dep.ts";

export class HandshakeRole extends Enum {
   static CLIENT = new HandshakeRole('CLIENT', 'CLIENT');
   static SERVER = new HandshakeRole('SERVER', 'SERVER')
}

export class FullHandshake {
   transcript = new TranscriptMsg;
   constructor(clientHelloHandshake, serverHelloHandshake, privateKey, role = HandshakeRole.CLIENT, _compare) {
      //TODO - validate arguments
      this.clientHello = clientHelloHandshake.message;
      this.serverHello = serverHelloHandshake.message;
      this.transcript.insert(clientHelloHandshake, serverHelloHandshake);
      this.cipher = this.serverHello.cipher;
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
      if (this.role == HandshakeRole.CLIENT) return this.serverHello.extensions.get(ExtensionType.KEY_SHARE).data.key_exchange;
      return this.clientHello.ext.get("KEY_SHARE").data.keyShareEntries.get(this.namedGroup)
   }
   get sharedSecret(){
      return this.namedGroup.keyGen.getSharedSecret(this.privateKey, this.peerKey)
   }
}

export function parseRecords(array) {
   return parseItems(array, 0, array.length, TLSPlaintext)//new Set
}

export async function parseServerHello(array, clientHello, clientPrivateKey) {
   if ((clientHello instanceof ClientHello) == false) clientHello = ClientHello.from(clientHello);
   const [serverHelloRecord, _changeCipherSpec, applicationData] = parseRecords(array);
   const fullHS = new FullHandshake(Handshake.fromClientHello(clientHello), serverHelloRecord.fragment, clientPrivateKey, HandshakeRole.CLIENT);
   const decrypted = await fullHS.aead_hs_s.decrypt(applicationData)
   const [encryptedExtsMsg, certificateMsg, certificateVerifyMsg, finishedMsg] = parseItems(decrypted.content, 0, decrypted.content.length, Handshake)
   const _isCertificateValid = await certificateMsg.message.verify();
   const _isCertificateVerifyValid = await verifyCertificateVerify(
      Handshake.fromClientHello(clientHello),
      serverHelloRecord.fragment,
      encryptedExtsMsg,
      certificateMsg,
      certificateVerifyMsg
   )
   const expectedFinished = await finished(
      fullHS.finished_key_s, fullHS.cipher.hashLength*8, 
      Handshake.fromClientHello(clientHello),
      serverHelloRecord.fragment,
      encryptedExtsMsg,
      certificateMsg,
      certificateVerifyMsg
   )
   const _isFinishedValid = expectedFinished.toString() == finishedMsg.message.toString() 
   return true;
}