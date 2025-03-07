import { ClientHello, HexaDecimal } from "../../src/dep.ts";


const clienHello_ = HexaDecimal.fromString(
   `16 03 01 01 3d 01 00 01 39 03 03 5b 3a 2a 90 bc
    ce 4d 72 e1 ec 0c 4d b9 5c a9 d2 1c 0c 09 22 54
    40 99 3b dd b9 0f 31 a4 95 15 8f 20 bc 03 b6 30
    7b 13 07 82 8e 8e a3 69 29 02 fe 30 8a fb ac 05
    b2 cc 3a 3f 7b 1f 41 39 59 c8 e8 b5 00 3e 13 02
    13 03 13 01 c0 2c c0 30 00 9f cc a9 cc a8 cc aa
    c0 2b c0 2f 00 9e c0 24 c0 28 00 6b c0 23 c0 27
    00 67 c0 0a c0 14 00 39 c0 09 c0 13 00 33 00 9d
    00 9c 00 3d 00 3c 00 35 00 2f 00 ff 01 00 00 b2
    00 00 00 13 00 11 00 00 0e 73 6d 74 70 2e 67 6d
    61 69 6c 2e 63 6f 6d 00 0b 00 04 03 00 01 02 00
    0a 00 16 00 14 00 1d 00 17 00 1e 00 19 00 18 01
    00 01 01 01 02 01 03 01 04 00 23 00 00 00 16 00
    00 00 17 00 00 00 0d 00 30 00 2e 04 03 05 03 06
    03 08 07 08 08 08 1a 08 1b 08 1c 08 09 08 0a 08
    0b 08 04 08 05 08 06 04 01 05 01 06 01 03 03 03
    01 03 02 04 02 05 02 06 02 00 2b 00 05 04 03 04
    03 03 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d
    00 20 ba 17 7d d8 b7 fd ec 28 73 45 41 23 1b d5
    f3 8b 36 a0 57 70 af 51 06 93 d1 a5 f3 63 c7 35
    db 79
    `
).byte;

const clientHello = ClientHello.from(clienHello_.slice(9));
const version = clientHello.version;
const random = clientHello.random;
const session = clientHello.legacy_session_id;
const ciphers = clientHello.ciphers;
debugger;