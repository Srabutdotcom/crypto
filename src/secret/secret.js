//@ts-self-types="../../type/secret/secret.d.ts"
import { DerivedSecret } from "../keyschedule/keyschedule.js";
import { hkdfExtract256, hkdfExtract384 } from "../hkdf/hkdf.js";
import { derivedSecret } from "../keyschedule/keyschedule.js";
import { hkdfExpandLabel } from "../keyschedule/keyschedule.js";

import { Aead } from "../aead/aead.js"
import { sha256, sha384, safeuint8array, Finished,/* Struct, HexaDecimal, SignatureScheme,  finished */} from "../dep.ts";
import { Transcript } from "./transcript.js";

export class Secret {
   keyLength;
   digestLength;
   namedGroup;
   derivedKey;
   sharedKey;
   hsKey;
   transcript = new Transcript;
   masterKey;
   hsTrafficKeyClient;
   hsTrafficKeyServer
   keyHSServer;
   ivHSServer;
   keyHSClient;
   ivHSClient;
   finishedKeyServer
   finishedKeyClient
   aeadHSServer;
   aeadHSClient;
   apKeyClient;
   apKeyServer;
   expMaster;
   resMaster;
   resumption;
   keyAPClient;
   keyAPServer;
   ivAPClient;
   ivAPServer;
   aeadAPServer;
   aeadAPClient;
   constructor(cipher, namedGroup, privateKey, publicKey, peerPublicKey) {
      this.cipher = cipher
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
         this.getHSSecret(this.sharedKey)
         this.getMasterKey()
      }
   }
   getHSSecret(sharedKey) {
      this.hsKey ||= this.hkdfExtract(this.derivedKey, sharedKey);
      return this.hsKey;
   }
   getSharedSecret(peerPublicKey) {
      if (this.sharedKey) return this.sharedKey;
      this.sharedKey = this.namedGroup.getSharedKey(peerPublicKey);
      return this.sharedKey;
   }
   updateHSKey(clientHelloMsg, serverHelloMsg) {
      //this.transcriptHSMsg ||= Struct.createFrom(clientHelloMsg, serverHelloMsg)
      this.transcript.insertMany(clientHelloMsg, serverHelloMsg);

      this.hsTrafficKeyClient ||= derivedSecret(this.hsKey, 'c hs traffic', this.transcript.byte, this.cipher.hashLength);
      this.hsTrafficKeyServer ||= derivedSecret(this.hsKey, 's hs traffic', this.transcript.byte, this.cipher.hashLength);
      this.keyHSServer ||= hkdfExpandLabel(this.hsTrafficKeyServer, "key", new Uint8Array, this.cipher.keyLength);
      this.ivHSServer ||= hkdfExpandLabel(this.hsTrafficKeyServer, "iv", new Uint8Array, 12);
      this.aeadHSServer = new Aead(this.keyHSServer, this.ivHSServer);
      this.keyHSClient ||= hkdfExpandLabel(this.hsTrafficKeyClient, "key", new Uint8Array(), this.cipher.keyLength);
      this.ivHSClient ||= hkdfExpandLabel(this.hsTrafficKeyClient, "iv", new Uint8Array(), 12);
      this.aeadHSClient ||= new Aead(this.keyHSClient, this.ivHSClient);
      this.finishedKeyServer ||= hkdfExpandLabel(this.hsTrafficKeyServer, 'finished', new Uint8Array, this.cipher.hashLength);
      this.finishedKeyClient ||= hkdfExpandLabel(this.hsTrafficKeyClient, 'finished', new Uint8Array, this.cipher.hashLength);
   }

   getMasterKey() {
      if (!this.masterKey) {
         const derivedMaster = derivedSecret(this.hsKey, 'derived', new Uint8Array, this.cipher.hashLength);
         this.masterKey = this.hkdfExtract(derivedMaster)
      }
      return this.masterKey;
   }

   set privateKey(key) { this.namedGroup.privateKey = key };
   set publicKey(key) { this.namedGroup.publicKey = key };
   async updateAPKey(encryptedExtMsg, certificateMsg, rsaPrivateKey, signaturescheme, certificateVerifyMsg_0, finishedMsg_0, finishedClientMsg_0) {
      this.transcript.insertMany(encryptedExtMsg, certificateMsg);
      const clientHelloMsg = this.transcript.clientHelloMsg;
      const serverHelloMsg = this.transcript.serverHelloMsg
      const certificateVerifyMsg = certificateVerifyMsg_0 ?? await signaturescheme.certificateVerify(clientHelloMsg, serverHelloMsg, encryptedExtMsg, certificateMsg, rsaPrivateKey);
      this.transcript.insert(certificateVerifyMsg);
      const finishedMsg = finishedMsg_0 ?? await finished(this.finishedKeyServer, this.digestLength * 8, clientHelloMsg, serverHelloMsg, encryptedExtMsg, certificateMsg, certificateVerifyMsg);
      this.transcript.insert(finishedMsg);

      this.apKeyClient ||= derivedSecret(this.masterKey, "c ap traffic", this.transcript.byte, this.cipher.hashLength);
      this.apKeyServer ||= derivedSecret(this.masterKey, "s ap traffic", this.transcript.byte, this.cipher.hashLength);
      this.expMaster ||= derivedSecret(this.masterKey, "exp master", this.transcript.byte, this.cipher.hashLength);
      this.keyAPServer ||= hkdfExpandLabel(this.apKeyServer, "key", new Uint8Array, this.cipher.keyLength);
      this.ivAPServer ||= hkdfExpandLabel(this.apKeyServer, "iv", new Uint8Array, 12);
      this.keyAPClient ||= hkdfExpandLabel(this.apKeyClient, "key", new Uint8Array, this.cipher.keyLength);
      this.ivAPClient ||= hkdfExpandLabel(this.apKeyClient, "iv", new Uint8Array, 12);
      this.aeadAPClient ||= new Aead(this.keyAPClient, this.ivAPClient);
      this.aeadAPServer ||= new Aead(this.keyAPServer, this.ivAPServer);

      const finishedClientMsg = finishedClientMsg_0 ?? await finished(this.finishedKeyServer, this.digestLength * 8, clientHelloMsg, serverHelloMsg, encryptedExtMsg, certificateMsg, certificateVerifyMsg, finishedMsg);
      this.transcript.insert(finishedClientMsg);

      this.resMaster ||= derivedSecret(this.masterKey, "res master", this.transcript.byte, this.cipher.hashLength);
      
   }
   getResumption(ticketNonce = Uint8Array.of(0,0)){
      this.resumption ||= hkdfExpandLabel(this.resMaster, 'resumption', ticketNonce, this.cipher.hashLength);
   }
}

async function finished(finishedKey, sha = 256, ...messages) {
   //const finishedKey = hkdfExpandLabel(serverHS_secret, 'finished', new Uint8Array, 32);
   const finishedKeyCrypto = await crypto.subtle.importKey(
      "raw",
      finishedKey,
      {
         name: "HMAC",
         hash: { name: `SHA-${sha}` },
      },
      true,
      ["sign", "verify"]
   );

   const hash = sha == 256 ? sha256.create() :
      sha == 384 ? sha384.create() : sha256.create();

   //const messagesStruct = Struct.createFrom(...messages);

   const transcriptHash = hash
      .update(safeuint8array(...messages))
      .digest();

   const verify_data = await crypto.subtle.sign(
      { name: "HMAC" },
      finishedKeyCrypto,
      transcriptHash
   )

   /* const _test_verify_data = await crypto.subtle.verify(
      { name: "HMAC" },
      finishedKeyCrypto,
      verify_data,
      transcriptHash
   ) */
   //verify_data.transcriptHash = transcriptHash;
   return new Finished(verify_data);
}


