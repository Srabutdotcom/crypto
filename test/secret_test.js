import { Cipher, HexaDecimal, NamedGroup } from "../src/dep.ts";
import { Secret } from "../src/secret/secret.js";

// Key- selected based on prefered curve 
const privateKey = HexaDecimal.fromString(
   `b1 58 0e ea df 6d d5 89 b8 ef 4f 2d 56
      52 57 8c c8 10 e9 98 01 91 ec 8d 05 83 08 ce a2 16 a2 1e
`).byte

const publicKey = HexaDecimal.fromString(`c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6
   72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f`).byte;

const peerPublicKey = HexaDecimal.fromString(`99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d
   ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c`).byte


const secret = new Secret(Cipher.AES_128_GCM_SHA256, NamedGroup.X25519, privateKey, publicKey, peerPublicKey);

const _n = null;