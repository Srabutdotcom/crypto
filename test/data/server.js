import { HexaDecimal, HandshakeType } from "../../src/dep.ts"

// Key- selected based on prefered curve 
export const serverPrivateKey = HexaDecimal.fromString(
   `b1 58 0e ea df 6d d5 89 b8 ef 4f 2d 56
   52 57 8c c8 10 e9 98 01 91 ec 8d 05 83 08 ce a2 16 a2 1e`).byte

export const serverPublicKey = HexaDecimal.fromString(
   `c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6
   72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f`).byte

export const serverHelloMsg = HexaDecimal.fromString(
   `02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e
   6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2
   69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11
   20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69
   b1 b0 4e 75 1f 0f 00 2b 00 02 03 04`).byte

export const handshakeKey = HexaDecimal.fromString(
   `1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b
   01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac`
).byte

export const masterKey = HexaDecimal.fromString(
   `18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a
   47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19`
).byte

export const keyHSServer = HexaDecimal.fromString(
   `3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e
   e4 03 bc`
).byte

export const ivHSServer = HexaDecimal.fromString(
   `5d 31 3e b2 67 12 76 ee 13 00 0b 30`
).byte

export const finishedKeyServer = HexaDecimal.fromString(
   `00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85
   c3 1f c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8`
).byte

export const finishedKeyClient = HexaDecimal.fromString(
   `b8 0a d0 10 15 fb 2f 0b d6 5f f7 d4 da 5d
   6b f8 3f 84 82 1d 1f 87 fd c7 d3 c7 5b 5a 7b 42 d9 c4`
).byte

export const encryptedExtensionsMsg = HandshakeType.ENCRYPTED_EXTENSIONS.handshake(HexaDecimal.fromString(`00 22 00 0a 00 14 00
   12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c
   00 02 40 01 00 00 00 00
`).byte).byte

export const certificateMsg = HexaDecimal.fromString(
`0b 00 01 b9 00 00 01 b5 00 01 b0 30 82
01 ac 30 82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48
86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03
72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17
0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06
03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7
0d 01 01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f
82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26
d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c
1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52
4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74
80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93
ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03
01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06
03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01
01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a
72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea
e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01
51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be
c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b
1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8
96 12 29 ac 91 87 b4 2b 4d e1 00 00`).byte;

export const certificateVerifyMsg = HexaDecimal.fromString(
   `0f 00 00 84 08 04 00 80 5a 74 7c
   5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a
   b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07
   86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b
   be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44
   5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a
   3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3`).byte

export const finishedMsg = HexaDecimal.fromString(
   `14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb
   dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07
   18`).byte

const rsaPrivateKeyJwk = JSON.parse('{"kty":"RSA","alg":"PS256","key_ops":["sign"],"ext":true,"n":"tLtJj4J5MD2YCDY5mzbGmIwMaN5V4b24JtOQGiRh6v0t5JqR0BWrvJqVE3rObBrxnqpq-Yx87UMSCZjhh6gO4MywUksbAYw-C2MmTUSabTjiKl_aQwhGdIAwUw7wRhyMqdnvv66OptHQPivRk-_wq5qAAsR0KKbTWo2I159_Hj8","e":"AQAB","d":"BN6nBdQ6bqcgndgHIRGoPIHjIqWSeLM0gGQer3wKaYW44xxE9t5i4bTCMJ9hJud7fEHpIzFLv6OIEwXcEhfxbIGc5TjpIvNpgo0OVxldjISIRgIHsvqnJrz3CLvX239nn4k0kvwqYi4IlwqsRBzk4MMIjfJa5nkjPfijvaL_mUE","p":"5DX7fMg3N3VtrOqWq39ZoswQadt96xkOF-M6UysnPzCjJ6oKqrxYzWdGavmEX63Gdf4JSvksS9Hywbwz3S4FFQ","q":"yr07wOBDhmTI1MyfmZd6lNm7_q2OQ4cKuuP364tODu6K8dm0cZumGWzyy7ru6_izSQr-np_6dKiKpR_GRWKTAw","dp":"P1c0XCf-G2h-bnYWJ7eLG4JkM912D6C-pqas85SQqhtHzaSGnWj1hN1bUCm9Mgk7glhmH-cVAl5dcKRaCNPTGQ","dq":"GD2gE2O9LyiFysvcmWS_R2TxUXY2-GQBKG9xiTxSzP5ApsI9DQhrR8b7ENj9EEHgTe9-mkDOlXxBd5ThBBLROQ","qi":"g5ypoIXkKGsskORmmXosaB8hM5qjR3gU5N7BGDMFDtUN0TzAOASKQ8WbKsxBaInAN2Zf5a-mBZafjAHfpcqWnQ"}');

export const rsaPrivateKey = await crypto.subtle.importKey('jwk', rsaPrivateKeyJwk, { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['sign'])

export const expMasterKey = HexaDecimal.fromString(
   `fe 22 f8 81 17 6e da 18 eb 8f 44 52 9e 67
   92 c5 0c 9a 3f 89 45 2f 68 d8 ae 31 1b 43 09 d3 cf 50`).byte;

export const keyAPServer = HexaDecimal.fromString(
   `9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac
   92 e3 56`).byte

export const ivAPServer = HexaDecimal.fromString(
   `cf 78 2b 88 dd 83 54 9a ad f1 e9 84`).byte

export const keyHSClient = HexaDecimal.fromString(
   `db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50
   25 8d 01`
).byte

export const ivHSClient = HexaDecimal.fromString(
   `5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f`
).byte

export const keyAPClient = HexaDecimal.fromString(
   `17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6
   3f 50 51`).byte

export const ivAPClient = HexaDecimal.fromString(
   `5b 78 92 3d ee 08 57 90 33 e5 23 d9`).byte

export const resMaster = HexaDecimal.fromString(
   `7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41
   b0 bf da f8 6c c8 56 23 1f 2d 5a ba 46 c4 34 ec 19 6c`).byte

export const finishedClientMsg = HexaDecimal.fromString(
   `14 00 00 20 a8 ec 43 6d 67 76 34 ae 52 5a
   c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce
   61`).byte

export const resumption = HexaDecimal.fromString(
   `4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c
   a4 c5 85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3`
).byte

export const newSessionTicket = HexaDecimal.fromString(
   `04 00 00 c9 00 00 00 1e fa d6 aa
   c5 02 00 00 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00 00 00
   00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70 ad 3c
   49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9 82 11
   72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6 1d 28
   27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0 37 25
   a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 90 6c
   5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5 ae a6
   17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d e6 50
   5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 00 08 00 2a 00
   04 00 00 04 00`
).byte;

export const data = HexaDecimal.fromString(
   `00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e
   0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23
   24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31`
).byte