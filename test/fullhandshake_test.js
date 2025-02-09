import { FullHandshake, HandshakeRole } from "../src/secret/fullhandshake.js";
import { clientHello, clientPrivateKey } from "../test/data_fullhandshake/fullhandshake_data.js";
import { serverHello, response } from "../test/data_fullhandshake/fullhandshake_data.js";
import { ClientHello, Handshake, ServerHello } from "../src/dep.ts";
import { TLSCiphertext, parseItems } from "../src/dep.ts";
import { EncryptedExtensions, Certificate, CertificateVerify, Finished } from "../src/dep.ts";
import { parseServerHello } from "../src/secret/fullhandshake.js";

/* const test = new FullHandshake(ClientHello.fromHandshake(clientHelloMsg), ServerHello.fromHandshake(serverHelloMsg), clientPrivateKey, HandshakeRole.CLIENT); */

//const test = new FullHandshake(Handshake.fromClientHello(clientHello), Handshake.fromServerHello(serverHello), clientPrivateKey, HandshakeRole.CLIENT);
const test_0 = await parseServerHello(response, clientHello, clientPrivateKey )

const decrypted = await test.aead_hs_s.open(TLSCiphertext.from(application_data));

const handshakes = parseItems(decrypted.content, 0, decrypted.content.length, Handshake);

const [encryptedExt, certificate, certificateVerify, finished] = handshakes;

//NOTE - encryptedExtension is temporarily ignored
const encryptedExtMsg = EncryptedExtensions.from(encryptedExt.message);
const certificateMsg = Certificate.from(certificate.message);
const certificateVerifyMsg = CertificateVerify.from(certificateVerify.message);
const finishedMsg = Finished.from(finished.message)

const isCertificateEntriesValid = await certificateMsg.verify()

debugger;