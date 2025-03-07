import { HexaDecimal, safeuint8array, ServerHello } from "../../src/dep.ts";
import { x25519 } from "../../src/dep.ts";
import { hkdfExtract256 } from "../../src/hkdf/hkdf.js";
import { clientPublicKey } from "./client.js";

export const serverPrivateKey = HexaDecimal.fromString(`de 5b 44 76 e7 b4 90 b2 65 2d 33 8a cb
         f2 94 80 66 f2 55 f9 44 0e 23 b9 8f c6 98 35 29 8d c1 07`).byte;

const _serverPublicKey = HexaDecimal.fromString(`12 17 61 ee 42 c3 33 e1 b9 e7 7b 60 dd 57
         c2 05 3c d9 45 12 ab 47 f1 15 e8 6e ff 50 94 2c ea 31`).byte;

export const serverHelloMsg = HexaDecimal.fromString(`02 00 00 5c 03 03 3c cf d2 de c8 90 22
         27 63 47 2a e8 13 67 77 c9 d7 35 87 77 bb 66 e9 1e a5 12 24 95
         f5 59 ea 2d 00 13 01 00 00 34 00 29 00 02 00 00 00 33 00 24 00
         1d 00 20 12 17 61 ee 42 c3 33 e1 b9 e7 7b 60 dd 57 c2 05 3c d9
         45 12 ab 47 f1 15 e8 6e ff 50 94 2c ea 31 00 2b 00 02 03 04`).byte;

const serverHelloMsg_0 = ServerHello.from(serverHelloMsg.slice(4));

export const derivedKey = HexaDecimal.fromString(`5f 17 90 bb d8 2c 5e 7d 37 6e d2 e1 e5 2f
         8e 60 38 c9 34 6d b6 1b 43 be 9a 52 f7 7e f3 99 8e 80`).byte

const IKM = x25519.getSharedSecret(serverPrivateKey, clientPublicKey);
const IKM_0 = HexaDecimal.fromString(`f4 41 94 75 6f f9 ec 9d 25 18 06 35 d6 6e a6 82
         4c 6a b3 bf 17 99 77 be 37 f7 23 57 0e 7c cb 2e`).byte;
const hsKey = hkdfExtract256(derivedKey, IKM);
const hsKey_0 = HexaDecimal.fromString(`00 5c b1 12 fd 8e b4 cc c6 23 bb 88 a0 7c 64
         b3 ed e1 60 53 63 fc 7d 0d f8 c7 ce 4f f0 fb 4a e6`).byte;

export const shs = HexaDecimal.fromString(`fe 92 7a e2 71 31 2e 8b f0 27 5b 58 1c 54
   ee f0 20 45 0d c4 ec ff aa 05 a1 a3 5d 27 51 8e 78 03`).byte
export const chs = HexaDecimal.fromString(`2f aa c0 8f 85 1d 35 fe a3 60 4f cb 4d e8
   2d c6 2c 9b 16 4a 70 97 4d 04 62 e2 7f 1a b2 78 70 0f`).byte

export const d_master_key = HexaDecimal.fromString(`e2 f1 60 30 25 1d f0 87 4b a1 9b 9a ba 25
         76 10 bc 6d 53 1c 1d d2 06 df 0c a6 e8 4a e2 a2 67 42`).byte;
export const master_key = HexaDecimal.fromString(`e2 d3 2d 4e d6 6d d3 78 97 a0 e8 0c 84 10 75
         03 ce 58 bf 8a ad 4c b5 5a 50 02 d7 7e cb 89 0e ce`).byte

export const serverHelloRecord_0 = safeuint8array(
   HexaDecimal.fromString(`16 03 03 00 60`).byte,
   serverHelloMsg
)
export const keyHSServer = HexaDecimal.fromString(`27 c6 bd c0 a3 dc ea 39 a4 73 26 d7 9b
         c9 e4 ee`).byte;
export const ivHSServer = HexaDecimal.fromString(`95 69 ec dd 4d 05 36 70 5e 9e f7 25`).byte

export const encryptedExtensionsMsg = HexaDecimal.fromString(`08 00 00 28 00 26 00 0a 00 14 00
         12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c
         00 02 40 01 00 00 00 00 00 2a 00 00`).byte

export const finishedKeyServer = HexaDecimal.fromString(`4b b7 4c ae 7a 5d c8 91 46 04 c0 bf be 2f
         0c 06 23 96 88 39 22 be c8 a1 5e 2a 9b 53 2a 5d 39 2c`).byte;

export const finished = HexaDecimal.fromString(`48 d3 e0 e1 b3 d9 07 c6 ac ff 14 5e 16 09
         03 88 c7 7b 05 c0 50 b6 34 ab 1a 88 bb d0 dd 1a 34 b2`).byte;

export const finishedMsg = safeuint8array(Uint8Array.of(0x14, 0, 0, 0x20), finished)

export const handshake_record = safeuint8array(encryptedExtensionsMsg, finishedMsg);

export const c_ap_traffic_key = HexaDecimal.fromString(`2a bb f2 b8 e3 81 d2 3d be be 1d d2 a7 d1
         6a 8b f4 84 cb 49 50 d2 3f b7 fb 7f a8 54 70 62 d9 a1`).byte

export const s_ap_traffic_key = HexaDecimal.fromString(`cc 21 f1 bf 8f eb 7d d5 fa 50 5b d9 c4 b4
         68 a9 98 4d 55 4a 99 3d c4 9e 6d 28 55 98 fb 67 26 91`).byte

export const exp_master_key = HexaDecimal.fromString(`3f d9 3d 4f fd dc 98 e6 4b 14 dd 10 7a ed
         f8 ee 4a dd 23 f4 51 0f 58 a4 59 2d 0b 20 1b ee 56 b4`).byte

export const write_traffic_key = HexaDecimal.fromString(`e8 57 c6 90 a3 4c 5a 91 29 d8 33 61 96
         84 f9 5e`).byte;
export const write_traffic_iv = HexaDecimal.fromString(`06 85 d6 b5 61 aa b9 ef 10 13 fa f9`).byte

const _n = null; 