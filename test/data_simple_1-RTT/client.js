import { AES, GCM, HexaDecimal } from "../../src/dep.ts";
import { ivXorSeq } from "../../play/nonce/nonce.js";

export const clientPrivateKey = HexaDecimal.fromString(
   `49 af 42 ba 7f 79 94 85 2d 71 3e f2 78
   4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05`).byte

export const clientPublicKey = HexaDecimal.fromString(
   `99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d
   ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c`).byte

export const clientHelloMsg = HexaDecimal.fromString(
   `01 00 00 c0 03 03 cb 34 ec b1 e7 81 63
   ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83
   02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b
   00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00
   12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23
   00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2
   3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a
   af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
   02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06
   02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01`).byte

export const key_traffic_app_server = HexaDecimal.fromString(
   `e8 57 c6 90 a3 4c 5a 91 29 d8 33 61 96
   84 f9 5e`
).byte

export const iv_traffic_app_server = HexaDecimal.fromString(
   `06 85 d6 b5 61 aa b9 ef 10 13 fa f9`
).byte;

export const key_traffic_app_client = HexaDecimal.fromString(
   `3c f1 22 f3 01 c6 35 8c a7 98 95 53 25
         0e fd 72`
).byte

export const iv_traffic_app_client = HexaDecimal.fromString(
   `ab 1a ec 26 aa 78 b8 fc 11 76 b9 ac`
).byte;

export const appDataClient = HexaDecimal.fromString(
   `17 03 03 00 43 b1 ce bc e2 42 aa 20
   1b e9 ae 5e 1c b2 a9 aa 4b 33 d4 e8 66 af 1e db 06 89 19 23 77
   41 aa 03 1d 7a 74 d4 91 c9 9b 9d 4e 23 2b 74 20 6b c6 fb aa 04
   fe 78 be 44 a9 b4 f5 43 20 a1 7e b7 69 92 af ac 31 03
   `).byte

export const appDataServer = HexaDecimal.fromString(
   `17 03 03 00 43 27 5e 9f 20 ac ff 57
   bc 00 06 57 d3 86 7d f0 39 cc cf 79 04 78 84 cf 75 77 17 46 f7
   40 b5 a8 3f 46 2a 09 54 c3 58 13 93 a2 03 a2 5a 7d d1 41 41 ef
   1a 37 90 0c db 62 ff 62 de e1 ba 39 ab 25 90 cb f1 94
   `
).byte;

export const alertClient = HexaDecimal.fromString(
   `17 03 03 00 13 0f ac ce 32 46 bd fc
         63 69 83 8d 6a 82 ae 6d e5 d4 22 dc`
).byte

export const alertServer = HexaDecimal.fromString(
   `17 03 03 00 13 5b 18 af 44 4e 8e 1e
         ec 71 58 fb 62 d8 f2 57 7d 37 ba 5d
   `
).byte

const gcm1 = new GCM(new AES(key_traffic_app_client));
const opened = gcm1.open(iv_traffic_app_client, appDataClient.subarray(5), appDataClient.subarray(0, 5));

const iv_1 = ivXorSeq(iv_traffic_app_client, 1);
console.log(iv_traffic_app_client.toString());
console.log(iv_1.toString());

const opened_alert_client = gcm1.open(iv_1, alertClient.subarray(5),alertClient.subarray(0,5));
console.log("opened alert client :", opened_alert_client?.toString())
debugger;

const gcm2 = new GCM(new AES(key_traffic_app_server));
const opened_1 = gcm2.open(iv_traffic_app_server, appDataServer.subarray(5), appDataServer.subarray(0, 5));

const key = Uint8Array.of(246, 30, 217, 70, 248, 123, 68, 147, 202, 123, 16, 105, 217, 26, 7, 190);
const iv = Uint8Array.of(34,124,93,208,73,90,2,188,221,51,98,230);
const data = Uint8Array.of(23,3,3,0,92,159,95,208,105,53,202,8,189,140,175,4,147,207,1,160,254,172,82,90,4,242,24,132,131,71,222,127,203,134,98,40,78,43,142,154,18,84,112,59,186,79,129,166,172,142,206,185,6,78,161,138,19,47,208,229,28,189,177,191,88,212,246,123,50,228,122,159,76,158,170,79,181,193,147,47,17,151,224,36,122,91,39,169,60,119,95,127,78,48,164,244,65);

const gcm3 = new GCM(new AES(key));
const opened_3 = gcm3.open(ivXorSeq(iv, 1), data.subarray(5), data.subarray(0, 5));
console.log(opened_3?.toString()??null)
debugger;