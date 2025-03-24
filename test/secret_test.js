import { Cipher, HexaDecimal, NamedGroup, SignatureScheme, ContentType, TLSCiphertext, TLSInnerPlaintext, Handshake, safeuint8array } from "../src/dep.ts";
import { Secret } from "../src/secret/secret.js";
import { serverPrivateKey, serverPublicKey, serverHelloMsg, data, completeRecord, newSessionTicketRecord } from "./data_simple_1-RTT/server.js";
import { clientPublicKey, clientHelloMsg } from "./data_simple_1-RTT/client.js";
import { handshakeKey, masterKey, keyHSServer, ivHSServer, finishedKeyServer } from "./data_simple_1-RTT/server.js";
import { encryptedExtensionsMsg, certificateMsg, rsaPrivateKey, certificateVerifyMsg, finishedMsg, finishedClientMsg } from "./data_simple_1-RTT/server.js";
import { expMasterKey, keyAPServer, ivAPServer, keyHSClient, ivHSClient } from "./data_simple_1-RTT/server.js";
import { keyAPClient, ivAPClient, finishedKeyClient, resMaster, resumption, finishedClientEncrypted } from "./data_simple_1-RTT/server.js";
import { newSessionTicket } from "./data_simple_1-RTT/server.js";
import { assertEquals } from "jsr:@std/assert"
import { ApplicationKey, HandshakeKey, HandshakeRole } from "../src/secret/fullhandshake.js";
import { ClientHello, ServerHello } from "../src/dep.ts";
import { Transcript } from "../src/secret/transcript.js";
import { finished } from "../src/finish/finish.js";

const secret = new Secret(Cipher.AES_128_GCM_SHA256, NamedGroup.X25519, serverPrivateKey, serverPublicKey, clientPublicKey);
//update handshake key
serverHelloMsg.isHRR = false
await secret.updateHSKey(clientHelloMsg, serverHelloMsg);
const transcript = new Transcript;
const clientHello_msg = Handshake.from(clientHelloMsg);
const serverHello_msg = Handshake.from(serverHelloMsg);
/* clientHello_msg.message.groups = new Map([
   [NamedGroup.X25519, clientPublicKey]
]) */
serverHello_msg.message.group = new Map([
   [NamedGroup.X25519, {privateKey:serverPrivateKey}]
])

Object.defineProperty(serverHello_msg, "isHRR", {
   value: false,  // Assign new value
   writable: true,  // Allow modification
   configurable: true,  // Allow redefinition
 });
transcript.insertMany(clientHello_msg, serverHello_msg)
const fullHS = new HandshakeKey(transcript)

const readBack = await secret.aeadHSServer.decrypt(completeRecord); 
const readBack_0 = await fullHS.aead_hs_s.decrypt(completeRecord);

await secret.updateAPKey(encryptedExtensionsMsg, certificateMsg, rsaPrivateKey, SignatureScheme.RSA_PSS_PSS_SHA256, 
   certificateVerifyMsg, finishedMsg, finishedClientMsg);
secret.getResumption()

transcript.insertMany(encryptedExtensionsMsg, certificateMsg, certificateVerifyMsg, finishedMsg)

const appKey = new ApplicationKey(fullHS, transcript, {
   masterKey,
   finishedKeyServer,
   finishedKeyClient,
   expMasterKey,
   keyAPServer,
   ivAPServer,
   keyAPClient,
   ivAPClient,
   resMaster,
   resumption
})

assertEquals(secret.hsKey, handshakeKey, "handshake key");
assertEquals(secret.masterKey, masterKey, "master key");
assertEquals(secret.keyHSServer, keyHSServer, "key handshake server");
assertEquals(secret.ivHSServer, ivHSServer, "iv handshake server");
assertEquals(secret.finishedKeyServer, finishedKeyServer, "finished key server")
assertEquals(secret.finishedKeyClient, finishedKeyClient, "finished key client")
assertEquals(secret.expMaster, expMasterKey, "exp master key")
assertEquals(secret.keyAPServer, keyAPServer, "key application server");
assertEquals(secret.ivAPServer, ivAPServer, "iv application server");
assertEquals(secret.keyHSClient, keyHSClient, "key handshake client");
assertEquals(secret.ivHSClient, ivHSClient, "iv handshake client");
assertEquals(secret.keyAPClient, keyAPClient, "key application client");
assertEquals(secret.ivAPClient, ivAPClient, "iv application client");
assertEquals(secret.resMaster, resMaster, "res master key");
assertEquals(secret.resumption, resumption, "resumption key");

fullHS.masterKey.toString() == masterKey.toString();
appKey.exporter_master_secret.toString() == expMasterKey.toString();

// create finishedMsgServer 
const finishedMsgServer_0 = await finished(
   fullHS.finished_key_s,
   safeuint8array(
   clientHelloMsg,
   serverHelloMsg,
   encryptedExtensionsMsg, certificateMsg, certificateVerifyMsg,
   ),
   serverHello_msg.message.cipher.hash
)
const finishedMsgClient_0 = await finished(
   fullHS.finished_key_c,
   safeuint8array(
   clientHelloMsg,
   serverHelloMsg,
   encryptedExtensionsMsg, certificateMsg, certificateVerifyMsg,
   Handshake.fromFinished(finishedMsgServer_0)
   ),
   serverHello_msg.message.cipher.hash
)

const finishedMsgClient_back = await secret.aeadHSClient.decrypt(finishedClientEncrypted)


// send to Client
const newSessionTicketRecord_1 = appKey.aead_server.seal(newSessionTicket, ContentType.HANDSHAKE)
const newSessionTicket_1_back = appKey.aead_server.open(newSessionTicketRecord_1);
console.log(`%cis newSessionTicketRecord The same :`, "color: green", newSessionTicketRecord_1.toString()==newSessionTicketRecord.toString())
console.log(`%cis newSessionTicket the same :`, "color: green", newSessionTicket_1_back.content.toString()==newSessionTicket.toString())

const newSessionTicketRecord_0 = await secret.aeadAPServer.encrypt(newSessionTicket, ContentType.HANDSHAKE)
const newSessionTicket_0_back = await secret.aeadAPServer.decrypt(newSessionTicketRecord_0);
console.log(`%cis newSessionTicketRecord The same :`, "color: green", newSessionTicketRecord_0.toString()==newSessionTicketRecord.toString())
console.log(`%cis newSessionTicket the same :`, "color: green", newSessionTicket_0_back.content.toString()==newSessionTicket.toString())

debugger;

// data from Client = 
const dataFromClient = await secret.aeadAPClient.encrypt(data, ContentType.APPLICATION_DATA);
const dataFromClient_0 = await secret.aeadAPClient.decrypt(dataFromClient);
// data from Server = 
const dataFromServer = await secret.aeadAPServer.encrypt(data, ContentType.APPLICATION_DATA); 
const dataFromServer_0 = await secret.aeadAPServer.decrypt(dataFromServer); 

// client send alert
const alertFromClient = await secret.aeadAPClient.encrypt(Uint8Array.of(1,0), ContentType.ALERT);
const alertFromClient_0 = await secret.aeadAPClient.decrypt(alertFromClient);
// server send alert
const alertFromServer = await secret.aeadAPServer.encrypt(Uint8Array.of(1,0), ContentType.ALERT);
const alertFromServer_0 = await secret.aeadAPServer.decrypt(alertFromServer);

const _n = null;