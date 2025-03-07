import { HandshakeKey, HandshakeRole } from "../src/secret/fullhandshake.js";
import { clientHello, clientPrivateKey } from "../test/data_fullhandshake/fullhandshake_data.js";
import { serverHello, response } from "../test/data_fullhandshake/fullhandshake_data.js";
import { AlertDescription, ClientHello, ContentType, Handshake, ServerHello } from "../src/dep.ts";
import { TLSCiphertext, parseItems } from "../src/dep.ts";
import { EncryptedExtensions, Certificate, CertificateVerify, Finished } from "../src/dep.ts";
import { parseHandshake } from "../src/secret/fullhandshake.js";

const clientHello_0 = ClientHello.from(clientHello)
clientHello_0.namedGroup = { privateKey: clientPrivateKey }

if (ContentType.from(response) == ContentType.ALERT) {
   throw Error(AlertDescription.BAD_RECORD_MAC.alert().description);
}
if (ContentType.from(response) == ContentType.HANDSHAKE) {
   const test_0 = await parseHandshake(response, clientHello_0);
   debugger;
}


//const decrypted = await test.aead_hs_s.open(application_data);

//const handshakes = parseItems(decrypted.content, 0, decrypted.content.length, Handshake);

//const [encryptedExt, certificate, certificateVerify, finished] = handshakes;

//NOTE - encryptedExtension is temporarily ignored
/* const encryptedExtMsg = EncryptedExtensions.from(encryptedExt.message);
const certificateMsg = Certificate.from(certificate.message);
const certificateVerifyMsg = CertificateVerify.from(certificateVerify.message);
const finishedMsg = Finished.from(finished.message)

const isCertificateEntriesValid = await certificateMsg.verify() */

debugger;

async function sendByte(conn, byte) {
   await conn.write(byte)
}

// Function to send a command to the server
async function sendCommand(conn, command) {
   const encoder = new TextEncoder();
   await conn.write(encoder.encode(command));
}

// Helper to base64 encode credentials
function _base64Encode(str) {
   const encoder = new TextEncoder();
   const bytes = encoder.encode(str);
   return btoa(String.fromCharCode(...bytes));
}

async function readByte(conn) {
   const reader = conn.readable.getReader();
   const { _done, value } = await reader.read();
   reader.releaseLock();
   return value
}

async function readDecode(conn) {
   const value = await readByte(conn)
   return decoder.decode(value)
}