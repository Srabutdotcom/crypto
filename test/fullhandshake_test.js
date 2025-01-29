import { FullHandshake, HandshakeRole } from "../src/secret/fullhandshake.js";
import { clientHello, clientPrivateKey } from "../test/data_fullhandshake/fullhandshake_data.js";
import { serverHello, application_data } from "../test/data_fullhandshake/fullhandshake_data.js";
import { ClientHello, Handshake, ServerHello } from "../src/dep.ts";
import { TLSCiphertext, parseItems } from "../src/dep.ts";

/* const test = new FullHandshake(ClientHello.fromHandshake(clientHelloMsg), ServerHello.fromHandshake(serverHelloMsg), clientPrivateKey, HandshakeRole.CLIENT); */

const test = new FullHandshake(ClientHello.from(clientHello), ServerHello.from(serverHello), clientPrivateKey, HandshakeRole.CLIENT);

const decrypted = await test.aead_hs_s.decrypt(TLSCiphertext.from(application_data));

const handshakes = parseItems(decrypted.content, 0, decrypted.content.length, Handshake)
