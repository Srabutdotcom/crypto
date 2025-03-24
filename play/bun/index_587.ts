console.log("Hello via Bun!");
import { EventEmitter } from "events";
//import Emitter from "component-emitter"
import { Emitter } from "../event/event.js";
import { Transcript } from "../../src/secret/transcript.js";
import { clientHelloForm } from "../connectls/clienthelloform.js";
import { parseRecords } from "../connectls/parserecord.js";

const emitter = new Emitter();
const decoder = new TextDecoder;

const eventObject = {
   data(socket: type, data) {
      //console.log(data.toString());
      this.data = data;
      emitter.emit("data");
   },
   open(socket) {
   },
   close(socket, error) {},
   drain(socket) {},
   error(socket, error) {},

   // client-specific handlers
   connectError(socket, error) {}, // connection failed
   end(socket) {}, // connection closed by server
   timeout(socket) {}, // connection timed out
   output: null,
};
debugger;
// The client
const socket = await Bun.connect({
   hostname: "smtp.gmail.com",
   port: 587,
   socket: eventObject,
});

async function getData() {
   return new Promise((resolve) => {
      emitter.on("data", () => {
         //console.log(socket.data)
         resolve(socket.data);
      });
   });
}

async function writeRead(data) {
   socket.write(`EHLO mail.example.com\r\n`);
   //console.log(dataStore?.data.toString());
   let output = await getData();
   return output;
}

async function writeDecode(data) {
   const byte = await writeRead(data);
   return decoder.decode(byte)
}

let response = ""

response = await writeDecode(`EHLO mail.example.com\r\n`);
console.log(response);
if (response.split('250').at(-1).startsWith('-')) {
   response = await getData();
   console.log(response);
   debugger;
}

response = await writeDecode("STARTTLS\r\n");
console.log(response);

const transcript = new Transcript;
const clientHello_Form = clientHelloForm(SMTP_SERVER);

const result = await sendClientHello(clientHello_Form);

async function sendClientHello(clientHelloForm) {
   // send clientHello record
   const clientHello = clientHelloForm.build;
   transcript.insert(clientHello.handshake);

   let response = await writeRead(clientHello.record);
   if (!response) throw Error(`Error no response`)

   const recordMap = parseRecords(response);

   const alert = recordMap.get(ContentType.ALERT);
   if (alert) throw Error(`Error : ${alert.fragment.description}`)
   const serverHelloRecord = recordMap.get(ContentType.HANDSHAKE);
   if (!serverHelloRecord) throw Error(`No serverHelloRecord`)

   if (serverHelloRecord.fragment.message.isHRR) {
      await clientHelloForm.updateNamedGroup(serverHelloRecord.fragment.message.extensions.get(ExtensionType.KEY_SHARE).data.group);
      console.log(`server hello retry msg-121 : ${serverHelloRecord.fragment}`)
      serverHelloRecord.fragment.isHRR = true;
      transcript.insert(serverHelloRecord.fragment)
      return await sendClientHello(dconn, clientHelloForm);
   }

   console.log(`serverHello msg-126 : ${serverHelloRecord.fragment.toString()}`)
   transcript.insert(serverHelloRecord.fragment)
   const fullHS = new HandshakeKey(transcript);

   const applicationData = recordMap.get(ContentType.APPLICATION_DATA);
   console.log(`Application data : length-${applicationData.length} `)//content: ${applicationData.toString()}

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
   const data = await appKey.aead_client.encrypt(encoder.encode("AUTH LOGIN"), ContentType.APPLICATION_DATA);
   response = await dconn.writeRead(
      //finishRecordEncrypted
      safeuint8array(
         changeCipherSpec,
         finishRecordEncrypted,
         data
      )
   )
   debugger;
   
   const decryptResponse = await appKey.aead_server.decrypt(response)
   debugger;
}
debugger;