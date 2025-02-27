import { Cipher, HexaDecimal, NamedGroup, SignatureScheme, ContentType, TLSCiphertext, TLSInnerPlaintext } from "../src/dep.ts";
import { Secret } from "../src/secret/secret.js";
import { serverPrivateKey, serverPublicKey, serverHelloMsg, data, completeRecord } from "./data_simple_1-RTT/server.js";
import { clientPublicKey, clientHelloMsg } from "./data_simple_1-RTT/client.js";
import { handshakeKey, masterKey, keyHSServer, ivHSServer, finishedKeyServer } from "./data_simple_1-RTT/server.js";
import { encryptedExtensionsMsg, certificateMsg, rsaPrivateKey, certificateVerifyMsg, finishedMsg, finishedClientMsg } from "./data_simple_1-RTT/server.js";
import { expMasterKey, keyAPServer, ivAPServer, keyHSClient, ivHSClient } from "./data_simple_1-RTT/server.js";
import { keyAPClient, ivAPClient, finishedKeyClient, resMaster, resumption } from "./data_simple_1-RTT/server.js";
import { newSessionTicket } from "./data_simple_1-RTT/server.js";
import { assertEquals } from "jsr:@std/assert"
import { HandshakeKey, HandshakeRole } from "../src/secret/fullhandshake.js";
import { ClientHello, ServerHello } from "../src/dep.ts";

const secret = new Secret(Cipher.AES_128_GCM_SHA256, NamedGroup.X25519, serverPrivateKey, serverPublicKey, clientPublicKey);
//update handshake key
await secret.updateHSKey(clientHelloMsg, serverHelloMsg);
const fullHS = new HandshakeKey(ClientHello.fromHandshake(clientHelloMsg), ServerHello.fromHandshake(serverHelloMsg), serverPrivateKey, HandshakeRole.SERVER, secret )

const readBack = await secret.aeadHSServer.decrypt(TLSCiphertext.from(completeRecord)); 
const readBack_0 = await fullHS.aead_hs_s.decrypt(TLSCiphertext.from(completeRecord));debugger;

await secret.updateAPKey(encryptedExtensionsMsg, certificateMsg, rsaPrivateKey, SignatureScheme.RSA_PSS_PSS_SHA256, 
   certificateVerifyMsg, finishedMsg, finishedClientMsg);
secret.getResumption()

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

const tlsInnerPlaintextOfNewSessionTicket = new TLSInnerPlaintext(newSessionTicket, ContentType.APPLICATION_DATA)
// send to Client
const newSessionTicketRecord = await secret.aeadAPServer.encrypt(tlsInnerPlaintextOfNewSessionTicket)
const newSessionTicketRecord_0 = await secret.aeadAPServer.decrypt(newSessionTicketRecord)

const dataContent = new TLSInnerPlaintext(data, ContentType.APPLICATION_DATA);
// data from Client = 
const dataFromClient = await secret.aeadAPClient.encrypt(dataContent);
const dataFromClient_0 = await secret.aeadAPClient.decrypt(dataFromClient);
// data from Server = 
const dataFromServer = await secret.aeadAPServer.encrypt(dataContent); 
const dataFromServer_0 = await secret.aeadAPServer.decrypt(dataFromServer); 

const alert =  new TLSInnerPlaintext(Uint8Array.of(1,0), ContentType.ALERT);
// client send alert
const alertFromClient = await secret.aeadAPClient.encrypt(alert);
const alertFromClient_0 = await secret.aeadAPClient.decrypt(alertFromClient);
// server send alert
const alertFromServer = await secret.aeadAPServer.encrypt(alert);
const alertFromServer_0 = await secret.aeadAPServer.decrypt(alertFromServer);

const _n = null;