// openssl s_client -starttls smtp -connect smtp.gmail.com:587 -crlf -quiet -msg

import { nodeConnect } from "./connector.js";
import { Transcript } from "../../src/secret/transcript.js";
import { clientHelloForm } from "./clienthelloform.js";
import { parseHandshakes, parseRecords } from "./parserecord.js";
import { ContentType, ExtensionType, Handshake, HandshakeType, verifyCertificateVerify, safeuint8array } from "../../src/dep.ts";
import { ApplicationKey, HandshakeKey } from "../../src/secret/fullhandshake.js";
import { verifyFinished, createFinished } from "../../src/finish/finish.js";

const encoder = new TextEncoder

const SMTP_SERVER = "smtp.gmail.com";//"smtp.zoho.com";//"smtp.yandex.com";//"smtp-mail.outlook.com"; //"mail.gmx.com";//"localhost";//"testtls.com";//
const SMTP_PORT = 587; // For TLS

const nSock = await nodeConnect({ port: SMTP_PORT, host: SMTP_SERVER });
let res = await nSock.readString(); 
console.log(res)

res = await nSock.writeString(`EHLO mail.example.com\r\n`); 
console.log(res)

if (res.split('250').at(-1).startsWith('-')) {
   res = await nSock.readString();
   console.log(res)
}
res = await nSock.writeString("STARTTLS\r\n");
console.log(res)

const transcript = new Transcript;
const clientHello_Form = clientHelloForm(SMTP_SERVER);

const result = await sendClientHello(nSock, clientHello_Form);

async function sendClientHello(sock, clientHelloForm) {
   // send clientHello record
   const clientHello = clientHelloForm.build;
   transcript.insert(clientHello.handshake);

   let response = await sock.writeRead(clientHello.record);
   if (!response) throw Error(`Error no response`);
   //console.log(response);

   const recordMap = parseRecords(response);

   const alert = recordMap.get(ContentType.ALERT);
   if (alert) throw Error(`Error : ${alert.fragment.description}`)
   const serverHelloRecord = recordMap.get(ContentType.HANDSHAKE);
   if (!serverHelloRecord) throw Error(`No serverHelloRecord`)

   if (serverHelloRecord.fragment.message.isHRR) {
      await clientHelloForm.updateNamedGroup(serverHelloRecord.fragment.message.extensions.get(ExtensionType.KEY_SHARE).data.group);
      console.log(`server hello retry msg-121 : ${serverHelloRecord.fragment.toString()}`)
      serverHelloRecord.fragment.isHRR = true;
      transcript.insert(serverHelloRecord.fragment)
      return await sendClientHello(sock, clientHelloForm);
   }

   // console.log(`serverHello msg-126 : ${serverHelloRecord.fragment.toString()}`)
   transcript.insert(serverHelloRecord.fragment)
   const fullHS = new HandshakeKey(transcript);

   // NOTE - some server send application data in the next chunk
   const applicationData = recordMap.get(ContentType.APPLICATION_DATA) ?? await sock.read();
   console.log(`%cApplication data : length-$`,"color: green", applicationData.length)

   const decrypted = await fullHS.aead_hs_s.decrypt(applicationData)

   const handshakeMap = parseHandshakes(decrypted.content)

   const _isCertificateValid = await handshakeMap.get(HandshakeType.CERTIFICATE).message.verify();
   let handshake = handshakeMap.get(HandshakeType.ENCRYPTED_EXTENSIONS)
   if (handshake) transcript.insert(handshake)
   handshake = handshakeMap.get(HandshakeType.CERTIFICATE_REQUEST);
   if (handshake) transcript.insert(handshake)
   handshake = handshakeMap.get(HandshakeType.CERTIFICATE);
   if (handshake) transcript.insert(handshake)

   const isCertificateVerifyValid = await verifyCertificateVerify(
      transcript,
      handshakeMap.get(HandshakeType.CERTIFICATE_VERIFY)//certificateVerifyMsg
   )
   if (isCertificateVerifyValid == false) throw Error(`Invalid certificateVerify`)

   const isFinishedValid = await verifyFinished(fullHS.finished_key_s, transcript, handshakeMap.get(HandshakeType.FINISHED))
   if (isFinishedValid == false) throw Error(`Invalid finishedMsg`)

      const appKey = new ApplicationKey(fullHS, transcript);

   const finishedClientMsg = await createFinished(fullHS.finished_key_c, transcript);
   //const combineCertificateFinishedClientMsg = safeuint8array(certificateClientMsg, finishedClientMsg)
   /**
    * LINK https://www.rfc-editor.org/rfc/rfc8446#section-4.4.4
    * Any records following a Finished message MUST be encrypted under the
      appropriate application traffic key as described in Section 7.2.
    */
   const finishRecordEncrypted = await fullHS.aead_hs_c.encrypt(finishedClientMsg, ContentType.HANDSHAKE);
   const changeCipherSpec = recordMap.get(ContentType.CHANGE_CIPHER_SPEC)

   // when connect to smtp port 465 the first thing is to send clientFinishedRecord
   const data = await appKey.aead_client.encrypt(encoder.encode("EHLO localhost\r\n"), ContentType.APPLICATION_DATA);
   response = await sock.writeRead(
      //finishRecordEncrypted
      safeuint8array(
         changeCipherSpec,
         finishRecordEncrypted,
         data
      )
   )
   console.log("%cresponse :", "color:green", response);
   const records = parseRecords(response, "array");
   
   const decrypteds = []
   for (const record of records){
      console.log(record.toString())
      console.log('key', appKey.aead_server.key)
      console.log('iv', appKey.aead_server.iv)
      const decrypt = await appKey.aead_server.decrypt(record);
      decrypteds.push(decrypt)   
   }
   //const session_2 = await appKey.aead_server.decrypt(recordMap_0[1]);
   debugger;
}

nSock.close();