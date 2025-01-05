import { hkdfExtract384, hkdfExtract256 } from "../hkdf/hkdf.js";
import { derivedSecret, hkdfExpandLabel } from "../keyschedule/keyschedule.js";
import { Aead } from "../aead/aead.js"
import { /* hmac, */ NamedGroup, p256, p384, p521, sha256, sha384, x25519, x448 } from "../dep.ts";
import { PskBinderEntry, Binders } from "../dep.ts"
import { ClientHello, HexaDecimal } from "../dep.ts"
import { TranscriptMsg } from "./transcript.js";
/* import { HMAC } from "@stablelib/hmac";
import { SHA256 } from "@stablelib/sha256";
import { SHA384 } from "@stablelib/sha384"; */


export class Resumed {
   // key storage
   early_key
   binder_key
   finish_key
   // hkdfExtract function
   hkdfExtract
   // clientHelloRecord
   clientHelloRecord
   // initialClientHello
   initClientHello
   // sha
   sha
   // binders function
   _binders = binders
   // derived key
   derived_key
   // IKM aka sharedKey
   IKM
   // handshake key
   handshake_key
   // transcript message
   transcript = new TranscriptMsg;
   // derived master key
   derived_master_key
   // master key
   master_key
   keyHSServer
   ivHSServer
   aeadHSServer
   constructor(resumptionKey, clientHelloMsg, sha = 256, keyLength = 16) {
      this.hkdfExtract = sha == 256 ? hkdfExtract256 : sha == 384 ? hkdfExtract384 : hkdfExtract256
      this.early_key = this.hkdfExtract(Uint8Array.of(), resumptionKey)
      this.binder_key = derivedSecret(this.early_key, "res binder", Uint8Array.of())
      this.finish_key = hkdfExpandLabel(this.binder_key, 'finished', Uint8Array.of())
      this.initClientHello = clientHelloMsg
      this.sha = sha
      this.keyLength = keyLength
   }
   async addBindersToClientHello(){
      const binders = await this._binders(this.finish_key, this.initClientHello, this.sha );
      this.clientHelloRecord = addBinders(binders, this.initClientHello);
      this.client_early_traffic_secret = derivedSecret(this.early_key, "c e traffic", this.clientHelloRecord.fragment);
      this.early_exporter_master_secret = derivedSecret(this.early_key, "e exp master", this.clientHelloRecord.fragment);
      this.keyAPClient ||= hkdfExpandLabel(this.client_early_traffic_secret, "key", new Uint8Array, this.keyLength);
      this.ivAPClient ||= hkdfExpandLabel(this.client_early_traffic_secret, "iv", new Uint8Array, 12);
      this.aeadAPClient ||= new Aead(this.keyAPClient, this.ivAPClient);
      this.derived_key ||= derivedSecret(this.early_key, "derived")
      this.transcript.insert(this.clientHelloRecord.fragment)
      return this.clientHelloRecord;
   }
   handshake(privateKey, peerPublicKey, group){
      switch (group) {
         case NamedGroup.X25519.name : {
            this.group = x25519; break;
         }
         case NamedGroup.X448.name : {
            this.group = x448; break;
         }
         case NamedGroup.SECP256R1 :{
            this.group = p256; break;
         }
         case NamedGroup.SECP384R1 : {
            this.group = p384; break;
         }
         case NamedGroup.SECP521R1 : {
            this.group = p521; break;
         }
         default:
            this.group = x25519
            break;
      }
      this.IKM = this.group.getSharedSecret(privateKey, peerPublicKey);
      this.handshake_key = this.hkdfExtract(this.derived_key, this.IKM)
   }
   deriveHandshake(serverHelloMsg){
      this.transcript.insert(serverHelloMsg);
      this.hsTrafficKeyClient ||= derivedSecret(this.handshake_key, 'c hs traffic', this.transcript.byte);
      this.hsTrafficKeyServer ||= derivedSecret(this.handshake_key, 's hs traffic', this.transcript.byte);
      this.derived_master_key ||= derivedSecret(this.handshake_key, "derived")
      this.master_key = this.hkdfExtract(this.derived_master_key)
      this.keyHSServer ||= hkdfExpandLabel(this.hsTrafficKeyServer, "key", new Uint8Array, this.keyLength);
      this.ivHSServer ||= hkdfExpandLabel(this.hsTrafficKeyServer, "iv", new Uint8Array, 12);
      this.aeadHSServer ||= new Aead(this.keyHSServer, this.ivAPClient);
   }
}

async function finished(finish_key, clientHelloMsg, sha = 256) {
   const finishedKeyCrypto = await crypto.subtle.importKey(
      "raw",
      finish_key,
      {
         name: "HMAC",
         hash: { name: `SHA-${sha}` },
      },
      true,
      ["sign", "verify"]
   );

   const hash = sha == 256 ? sha256.create() :
      sha == 384 ? sha384.create() : sha256.create();

   const transcriptHash = hash
      .update(clientHelloMsg)
      .digest();

   const finished_0 = await crypto.subtle.sign(
      { name: "HMAC" },
      finishedKeyCrypto,
      transcriptHash
   )

/*    const hash_1 = sha == 256 ? sha256 : sha == 384 ? sha384 : sha256;
   const hash_2 = sha == 256 ? SHA256 : sha == 384 ? SHA384 : SHA256;

   const finished_1 = hmac
   .create(hash_1, finish_key)
   .update(transcriptHash)
   .digest();

   const finished_2 = new HMAC(hash_2, finish_key)
   finished_2.update(transcriptHash)
   const finished_3 = finished_2.digest(); */

   /* const _test_verify_data = await crypto.subtle.verify(
      { name: "HMAC" },
      finishedKeyCrypto,
      verify_data,
      transcriptHash
   ) */
   //verify_data.transcriptHash = transcriptHash;
   return new Uint8Array(finished_0);
}

async function binders(finish_key, clientHelloMsg, sha = 256) {
   const binderPos = ClientHello.fromHandShake(clientHelloMsg).binderPos() + 4 ;
   const finished_0 = await finished(finish_key, Uint8Array.from(clientHelloMsg).slice(0, binderPos), sha)
   const binder = PskBinderEntry.fromBinderEntry(finished_0);
   return Binders.fromBinders(binder)
}

function addBinders(binders, clientHelloMsg) {
   // add to clientHelloMsg;
   const clientHelloMsg_0 = ClientHello.fromHandShake(clientHelloMsg);
   const clientHelloMsg_1  = clientHelloMsg_0.addBinders(binders);
   return clientHelloMsg_1.toRecord();
}
