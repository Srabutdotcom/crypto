import { /* finished, */ HexaDecimal } from "../../src/dep.ts";
import { derivedSecret, DerivedSecret, hkdfExpandLabel } from "../../src/keyschedule/keyschedule.js";
import { hkdfExtract256 } from "../../src/hkdf/hkdf.js";
import { sha256 } from "../../src/dep.ts";
import { hmac } from "@noble/hashes/hmac"

const _clientPrivateKey = HexaDecimal.fromString(
   `bf f9 11 88 28 38 46 dd 6a 21 34 ef 71
   80 ca 2b 0b 14 fb 10 dc e7 07 b5 09 8c 0d dd c8 13 b2 df`).byte

export const clientPublicKey = HexaDecimal.fromString(
   `e4 ff b6 8a c0 5f 8d 96 c9 9d a2 66 98 34
   6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b`).byte

export const clientHelloMsg = HexaDecimal.fromString(
   `01 00 01 fc 03 03 1b c3 ce b6 bb e3 9c
   ff 93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 d7 b4 bc 41 9d 78
   76 48 7d 95 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00 00 0b
   00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00
   12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 33
   00 26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d 96 c9 9d a2 66 98
   34 6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b 00 2a
   00 00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
   02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06
   02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01 00 15 00 57 00 00
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   00 00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9
   00 00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00
   70 ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3
   a9 82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f
   d6 1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e
   e0 37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f
   a5 90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97
   b5 ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f
   7d e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 fa d6
   aa cb`).byte

export const earlyKey = HexaDecimal.fromString(`9b 21 88 e9 b2 fc 6d 64 d7 1d c3 29 90 0e 20
         bb 41 91 50 00 f6 78 aa 83 9c bb 79 7c b7 d8 33 2c`).byte;

export const binderKey = HexaDecimal.fromString(`69 fe 13 1a 3b ba d5 d6 3c 64 ee bc c3 0e 39 5b
         9d 81 07 72 6a 13 d0 74 e3 89 db c8 a4 e4 72 56`).byte;

export const finishKey = HexaDecimal.fromString(`55 88 67 3e 72 cb 59 c8 7d 22 0c af fe 94
         f2 de a9 a3 b1 60 9f 7d 50 e9 0a 48 22 7d b9 ed 7e aa`).byte;

export const finished = HexaDecimal.fromString(`3a dd 4f b2 d8 fd f8 22 a0 ca 3c f7 67 8e
         f5 e8 8d ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f 9d`).byte

export const clientHelloRecord = HexaDecimal.fromString(`
      16 03 01 02 00 01 00 01 fc 03 03 1b c3 ce b6 bb e3 9c ff
      93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 d7 b4 bc 41 9d 78 76
      48 7d 95 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00 00 0b 00
      09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12
      00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 33 00
      26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d 96 c9 9d a2 66 98 34
      6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b 00 2a 00
      00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02
      03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02
      02 02 00 2d 00 02 01 01 00 1c 00 02 40 01 00 15 00 57 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
      00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00
      00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70
      ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9
      82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6
      1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0
      37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5
      90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5
      ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d
      e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 fa d6 aa
      cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca 3c f7 67 8e f5 e8 8d
      ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f 9d`).byte;

export const ce_trafficKey = HexaDecimal.fromString(`3f bb e6 a6 0d eb 66 c3 0a 32 79 5a ba 0e
         ff 7e aa 10 10 55 86 e7 be 5c 09 67 8d 63 b6 ca ab 62`).byte;

export const e_exp_trafficKey = HexaDecimal.fromString(`b2 02 68 66 61 09 37 d7 42 3e 5b e9 08 62
         cc f2 4c 0e 60 91 18 6d 34 f8 12 08 9f f5 be 2e f7 df`).byte;

/* const resumption = HexaDecimal.fromString(`4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c
      a4 c5 85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3`).byte
const prk = HexaDecimal.fromString(`69 fe 13 1a 3b ba d5 d6 3c 64 ee bc c3 0e 39 5b
      9d 81 07 72 6a 13 d0 74 e3 89 db c8 a4 e4 72 56`).byte

const earlyKey = hkdfExtract256(Uint8Array.of(), resumption); 

const binderKey = derivedSecret(earlyKey, "res binder", Uint8Array.of()); // prk
const finishKey =  hkdfExpandLabel(binderKey, 'finished', Uint8Array.of()); // expanded.
const pskBinder = await finished(finishKey, 256, clientHelloMsg); 
const pskBinder_0 = hmac(sha256, finishKey, clientHelloMsg )

const hash = await crypto.subtle.digest({name:"SHA-256"},clientHelloMsg);
const hashMsg = new Uint8Array(hash) */

export const keyHSClient = HexaDecimal.fromString(`b1 53 08 06 f4 ad fe ac 83 f1 41 30 32
         bb fa 82`).byte;
export const ivHSClient = HexaDecimal.fromString(`eb 50 c1 6b e7 65 4a bf 99 dd 06 d9`).byte

export const finishClient = HexaDecimal.fromString(`72 30 a9 c9 52 c2 5c d6 13 8f c5 e6 62 83
      08 c4 1c 53 35 dd 81 b9 f9 6b ce a5 0f d3 2b da 41 6d`).byte;

export const keyAPClient = HexaDecimal.fromString(`3c f1 22 f3 01 c6 35 8c a7 98 95 53 25
         0e fd 72`).byte;
export const ivAPClient = HexaDecimal.fromString(`ab 1a ec 26 aa 78 b8 fc 11 76 b9 ac`).byte

export const res_master_key = HexaDecimal.fromString(`5e 95 bd f1 f8 90 05 ea 2e 9a a0 ba 85 e7
         28 e3 c1 9c 5f e0 c6 99 e3 f5 be e5 9f ae bd 0b 54 06`).byte;




