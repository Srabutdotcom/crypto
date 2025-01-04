import { resumption } from "./data simple 1-RTT/server.js";
import { binderKey, ce_trafficKey, clientHelloMsg, clientHelloRecord, e_exp_trafficKey, earlyKey, finishKey } from "./data resumed 0-RTT/client.js";
import { binders } from "../src/secret/pskbinder.js";
import { assertEquals } from "@std/assert";
import { HexaDecimal, ClientHello, ContentType } from "../src/dep.ts";
import { derivedSecret } from "../src/keyschedule/keyschedule.js"
import { Resumed } from "../src/secret/resumed.js";

// create pskBinder
// const pskBinder = await finished(resumption, 256, clientHelloMsg);
const pskBinder_0 = HexaDecimal.fromString(`3a dd 4f b2 d8 fd f8 22 a0 ca 3c f7 67 8e
         f5 e8 8d ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f 9d`).byte
// assertEquals(pskBinder.toString(), pskBinder_0.toString())

// create binders
const binders_0 = await binders(clientHelloMsg, 256, resumption);

// add to clientHelloMsg;
const clientHelloMsg_0 = ClientHello.fromHandShake(clientHelloMsg);
const clientHelloMsg_1 = clientHelloMsg_0.addBinders(binders_0);
// clientHelloRecord;
const _clientHelloRecord = clientHelloMsg_1.toRecord();

// client_early_traffic_secret
const client_early_traffic_secret = derivedSecret(earlyKey, "c e traffic", _clientHelloRecord.fragment);
// early_exporter_master_secret
const early_exporter_master_secret = derivedSecret(earlyKey, "e exp master", _clientHelloRecord.fragment);

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
const decrypted = await resumed.aeadAPClient.decrypt(encrytped)

const _n = null; 