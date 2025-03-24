import { resumption } from "./data_simple_1-RTT/server.js";
import { binderKey, ce_trafficKey, clientHelloMsg, clientHelloRecord, 
   e_exp_trafficKey, earlyKey, finishKey, keyHSClient, ivHSClient,
   keyAPClient, ivAPClient,
   res_master_key,
} from "./data_resumed_0-RTT/client.js";
import { binders } from "../src/secret/pskbinder.js";
import { assertEquals } from "@std/assert";
import { HexaDecimal, ClientHello, ContentType, NamedGroup, ServerHello, TLSInnerPlaintext, TLSPlaintext, Handshake } from "../src/dep.ts";
import { derivedSecret } from "../src/keyschedule/keyschedule.js"
import { Resumed } from "../src/secret/resumed.js";
import { serverPrivateKey, serverHelloMsg, chs, shs, d_master_key, master_key, encryptedExtensionsMsg, finishedKeyServer, c_ap_traffic_key, s_ap_traffic_key, write_traffic_key, write_traffic_iv, exp_master_key } from "./data_resumed_0-RTT/server.js";
import { clientPublicKey } from "./data_resumed_0-RTT/client.js";
import { serverHelloRecord_0, ivHSServer, keyHSServer, } from "./data_resumed_0-RTT/server.js";
import { EncryptedExtensions, EndOfEarlyData } from "../src/dep.ts"
import { derivedKey } from "./data_resumed_0-RTT/server.js";
import { Alert, AlertDescription } from "jsr:@tls/enum@~0.4.9";

const resumed = new Resumed(resumption, clientHelloMsg, 256);
await resumed.addBindersToClientHello();

assertEquals(resumed.early_key.toString(), earlyKey.toString());
assertEquals(resumed.derived_key.toString(), derivedKey.toString())
assertEquals(resumed.binder_key.toString(), binderKey.toString());
assertEquals(resumed.finish_key.toString(), finishKey.toString());
assertEquals(resumed.clientHelloRecord.toString(), clientHelloRecord.toString()); // FIXME
assertEquals(resumed.client_early_traffic_secret.toString(), ce_trafficKey.toString());
assertEquals(resumed.early_exporter_master_secret.toString(), e_exp_trafficKey.toString());

const data = HexaDecimal.fromString(`41 42 43 44 45 46`).byte;

const encrytped = await resumed.aeadEarlyAppClient.encrypt(data, ContentType.APPLICATION_DATA);
const decrypted = await resumed.aeadEarlyAppClient.decrypt(encrytped);

// from serverside
resumed.handshake(serverPrivateKey, clientPublicKey, NamedGroup.X25519);
resumed.deriveHandshake(serverHelloMsg);

assertEquals(resumed.hsTrafficKeyClient.toString(), chs.toString())
assertEquals(resumed.hsTrafficKeyServer.toString(), shs.toString())
assertEquals(resumed.derived_master_key.toString(), d_master_key.toString())
assertEquals(resumed.master_key.toString(), master_key.toString())

const serverHelloRecord = TLSPlaintext.fromHandshake(serverHelloMsg);
assertEquals(serverHelloRecord.toString(), serverHelloRecord_0.toString())

assertEquals(resumed.keyHSServer.toString(), keyHSServer.toString());
assertEquals(resumed.ivHSServer.toString(), ivHSServer.toString())

const encryptedExtensionsMsg_0 = TLSPlaintext.fromHandshake(encryptedExtensionsMsg).fragment;

assertEquals(resumed.finishedKeyServer.toString(), finishedKeyServer.toString())

const finish = await resumed.derivedFinish(encryptedExtensionsMsg_0);

assertEquals(resumed.apKeyClient.toString(), c_ap_traffic_key.toString())
assertEquals(resumed.apKeyServer.toString(), s_ap_traffic_key.toString())
assertEquals(resumed.keyAPServer.toString(), write_traffic_key.toString())
assertEquals(resumed.ivAPServer.toString(), write_traffic_iv.toString())
assertEquals(resumed.expMaster.toString(), exp_master_key.toString())

// Client Side
// resumed.derived_key == Server Side

/*
{cli ent}  extract secret "handshake" (same as server handshake
   secret)

{client}  derive secret "tls13 c hs traffic" (same as server)

{client}  derive secret "tls13 s hs traffic" (same as server)

{client}  derive secret for master "tls13 derived" (same as server)

{client}  extract secret "master" (same as server master secret)

{client}  derive read traffic keys for handshake data (same as server
   handshake data write traffic keys)

{client}  calculate finished "tls13 finished" (same as server)

{client}  derive secret "tls13 c ap traffic" (same as server)

{client}  derive secret "tls13 s ap traffic" (same as server)

{client}  derive secret "tls13 exp master" (same as server)

{client}  construct an EndOfEarlyData handshake message: 
*/

const endOfEarlyData = new EndOfEarlyData();
const encryptedEODD = await resumed.aeadHSClient.encrypt(new TLSInnerPlaintext(endOfEarlyData.record, ContentType.APPLICATION_DATA))
const decryptedEODD = await resumed.aeadHSClient.decrypt(encryptedEODD);

assertEquals(resumed.keyHSClient.toString(), keyHSClient.toString());
assertEquals(resumed.ivHSClient.toString(), ivHSClient.toString())

const test = await resumed.derivedFinishClient();

assertEquals(resumed.keyAPClient.toString(), keyAPClient.toString());
assertEquals(resumed.ivAPClient.toString(), ivAPClient.toString())

assertEquals(resumed.res_master.toString(), res_master_key.toString())

/* 
{server}  derive read traffic keys for handshake data (same as client
   handshake data write traffic keys)

{server}  calculate finished "tls13 finished" (same as client)

{server}  derive read traffic keys for application data (same as
   client application data write traffic keys)

{server}  derive secret "tls13 res master" (same as client)
 */

const data_0 = HexaDecimal.fromString(`00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e
         0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23
         24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31`).byte;

const encryptedClient = await resumed.aeadAPClient.encrypt(data_0, ContentType.APPLICATION_DATA);
const decryptedClient = await resumed.aeadAPClient.decrypt(encryptedClient);

const encryptedServer = await resumed.aeadAPServer.encrypt(data_0, ContentType.APPLICATION_DATA);
const decryptedServer = await resumed.aeadAPServer.decrypt(encryptedServer);

const alert = Alert.fromAlertDescription(AlertDescription.CLOSE_NOTIFY);

const encAlertClient = await resumed.aeadAPClient.encrypt(alert,ContentType.APPLICATION_DATA);
const decAlertClient = await resumed.aeadAPClient.decrypt(encAlertClient);

const encAlertServer = await resumed.aeadAPServer.encrypt(alert,ContentType.APPLICATION_DATA);
const decAlertServer = await resumed.aeadAPServer.decrypt(encAlertServer);

const _n = null; 