import { Cipher, HexaDecimal, NamedGroup, SignatureScheme } from "../src/dep.ts";
import { Secret } from "../src/secret/secret.js";
import { serverPrivateKey, serverPublicKey, serverHelloMsg } from "./data/server.js";
import { clientPublicKey, clientHelloMsg } from "./data/client.js";
import { handshakeKey, masterKey, keyHSServer, ivHSServer, finishedKeyServer } from "./data/server.js";
import { encryptedExtensionsMsg, certificateMsg, rsaPrivateKey, certificateVerifyMsg, finishedMsg, finishedClientMsg } from "./data/server.js";
import { expMasterKey, keyAPServer, ivAPServer, keyHSClient, ivHSClient } from "./data/server.js";
import { keyAPClient, ivAPClient, finishedKeyClient, resMaster, resumption } from "./data/server.js";
import { assertEquals } from "jsr:@std/assert"

const secret = new Secret(Cipher.AES_128_GCM_SHA256, NamedGroup.X25519, serverPrivateKey, serverPublicKey, clientPublicKey);
//update handshake key
await secret.updateHSKey(clientHelloMsg, serverHelloMsg);
await secret.updateAPKey(encryptedExtensionsMsg, certificateMsg, rsaPrivateKey, SignatureScheme.RSA_PSS_PSS_SHA256, 
   certificateVerifyMsg, finishedMsg, finishedClientMsg);

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

const _n = null;