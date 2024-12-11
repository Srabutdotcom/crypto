import { x25519, x448, p256, p384, p521 } from "../src/dep.ts";
import { DerivedSecret } from "../src/keyschedule/keyschedule.js";
import { hkdfExtract384 } from "../src/hkdf/hkdf.js";

const privX25519 = x25519.utils.randomPrivateKey();
const privX448 = x448.utils.randomPrivateKey();
const privP256 = p256.utils.randomPrivateKey();
const privP384 = p384.utils.randomPrivateKey();
const privP521_1 = p521.utils.randomPrivateKey();
const privP521_2 = p521.utils.randomPrivateKey();

const sharedP521_1 = p521.getSharedSecret(privP521_1, p521.getPublicKey(privP521_2));
const handshakeSecret_1 = hkdfExtract384(DerivedSecret.SHA384, sharedP521_1)

const sharedP521_2 = p521.getSharedSecret(privP521_2, p521.getPublicKey(privP521_1));
const handshakeSecret_2 = hkdfExtract384(DerivedSecret.SHA384, sharedP521_2)

const n = null;