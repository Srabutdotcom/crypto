import { resumption } from "./data simple 1-RTT/server.js";
import { binderKey, ce_trafficKey, clientHelloMsg, clientHelloRecord, e_exp_trafficKey, earlyKey, finishKey } from "./data resumed 0-RTT/client.js";
import { binders } from "../src/secret/pskbinder.js";
import { assertEquals } from "@std/assert";
import { HexaDecimal, ClientHello, ContentType, NamedGroup, ServerHello } from "../src/dep.ts";
import { derivedSecret } from "../src/keyschedule/keyschedule.js"
import { Resumed } from "../src/secret/resumed.js";
import { serverPrivateKey, serverHelloMsg, chs, shs, d_master_key, master_key, encryptedExtensionsMsg, finishedKeyServer } from "../test/data resumed 0-RTT/server.js";
import { clientPublicKey } from "./data resumed 0-RTT/client.js";
import { serverHelloRecord_0, ivHSServer, keyHSServer, } from "../test/data resumed 0-RTT/server.js";
import { EncryptedExtensions } from "../src/dep.ts"

const resumed = new Resumed(resumption, clientHelloMsg, 256);
await resumed.addBindersToClientHello();

assertEquals(resumed.early_key.toString(), earlyKey.toString());
assertEquals(resumed.binder_key.toString(), binderKey.toString());
assertEquals(resumed.finish_key.toString(), finishKey.toString());
assertEquals(resumed.clientHelloRecord.toString(), clientHelloRecord.toString());
assertEquals(resumed.client_early_traffic_secret.toString(), ce_trafficKey.toString());
assertEquals(resumed.early_exporter_master_secret.toString(), e_exp_trafficKey.toString());

const data = HexaDecimal.fromString(`41 42 43 44 45 46`).byte;
const tlsInnerPlaintext = ContentType.APPLICATION_DATA.tlsInnerPlaintext(data);
const encrytped = await resumed.aeadAPClient.encrypt(tlsInnerPlaintext);
const decrypted = await resumed.aeadAPClient.decrypt(encrytped);

// from serverside
resumed.handshake(serverPrivateKey, clientPublicKey, NamedGroup.X25519);
resumed.deriveHandshake(serverHelloMsg);

assertEquals(resumed.hsTrafficKeyClient.toString(), chs.toString())
assertEquals(resumed.hsTrafficKeyServer.toString(), shs.toString())
assertEquals(resumed.derived_master_key.toString(), d_master_key.toString())
assertEquals(resumed.master_key.toString(), master_key.toString())

const serverHelloRecord = ServerHello.fromHandShake(serverHelloMsg).toRecord();
assertEquals(serverHelloRecord.toString(), serverHelloRecord_0.toString())

assertEquals(resumed.keyHSServer.toString(), keyHSServer.toString());
assertEquals(resumed.ivHSServer.toString(), ivHSServer.toString())

const encryptedExtensionsMsg_0 = EncryptedExtensions.fromHandshake(encryptedExtensionsMsg).handshake;

assertEquals(resumed.finishedKeyServer.toString(), finishedKeyServer.toString())

const finish = await resumed.derivedFinish(encryptedExtensionsMsg_0);

const _n = null; 