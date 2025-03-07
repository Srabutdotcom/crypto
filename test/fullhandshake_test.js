//openssl s_client -starttls smtp -debug -trace -connect smtp.gmail.com:587
//openssl s_client -starttls smtp -debug -trace -connect smtp-mail.outlook.com:587

import { HandshakeKey, HandshakeRole } from "../src/secret/fullhandshake.js";
import { clientHello as ch_sam , clientPrivateKey } from "../test/data_fullhandshake/fullhandshake_data.js";
import { serverHello/* , response */ } from "../test/data_fullhandshake/fullhandshake_data.js";
import { AlertDescription, ClientHello, ContentType, Handshake, ServerHello } from "../src/dep.ts";
import { TLSCiphertext, parseItems, TLSPlaintext, ExtensionType } from "../src/dep.ts";
import { EncryptedExtensions, Certificate, CertificateVerify, Finished } from "../src/dep.ts";
import { parseHandshake } from "../src/secret/fullhandshake.js";
import { NamedGroup } from "@tls/enum";
import { Extension, KeyShareClientHello, ServerNameList } from "@tls/extension";
import { safeuint8array, Uint16 } from "@tls/struct";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const SMTP_SERVER = "smtp.gmail.com"//"smtp-mail.outlook.com"; //
const SMTP_PORT = 587;  // For TLS

const conn = await Deno.connect({ hostname: SMTP_SERVER, port: SMTP_PORT, tcp: 'tcp' });

// Read initial server response
let response = await readDecode(conn);
console.log(response);

// Send HELO command
await sendCommand(conn, `HELO ${SMTP_SERVER}\r\n`);
response = await readDecode(conn);
console.log(response);

// Start TLS encryption (this step is optional if you are using port 465 with implicit SSL)
await sendCommand(conn, "STARTTLS\r\n");
response = await readDecode(conn);
console.log(response);

// Create ClientHello
// const namedGroup = NamedGroup.X25519;
 const clientHello = buildClientHello(SMTP_SERVER);// ClientHello.build(SMTP_SERVER);//
 const clientHelloRecord = clientHello.record;
//const clientHello = ClientHello.from(ch_sam);
/* let i = 0;
for (const a of clientHello){
   console.log(`index: ${i} - in a:  ${a} - in p: ${clientHello_0.at(i)}`); i++;
} */
//clientHello.namedGroup = { privateKey: clientPrivateKey }

// send ClientHello
await sendByte(conn,
   // clientHello.record
   clientHelloRecord
);

// read Response
response = await readByte(conn);
console.log('response: ')
console.log(response);

let finished_client
if(ContentType.from(response)==ContentType.ALERT){
   throw Error(AlertDescription.BAD_RECORD_MAC.alert().description);
}
if(ContentType.from(response)==ContentType.HANDSHAKE){
   finished_client = await parseHandshake(response, clientHello);
}

await sendByte(conn,
   safeuint8array(
      /* Uint8Array.of(3,3,20,0,1,1), */
      finished_client
   )
);

// read Response
response = await readByte(conn);
console.log('response: ')
console.log(response);

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

export function buildClientHello(...serverNames) {
   // derived from _clientHelloHead
   // NOTE - it seems that smpt.gmail.com doesn't support TLS_AES_256_GCM_SHA384 {0x13,0x02}
   const clientHelloHead = Uint8Array.of(3, 3, 238, 224, 243, 110, 198, 197, 21, 0, 31, 62, 170, 168, 11, 114, 76, 23, 125, 57, 4, 182, 125, 129, 85, 232, 67, 131, 111, 67, 131, 169, 63, 58, 0, 0, 6, 19, 1, 19, 2, 19, 3, 1, 0);

   // to make random 32
   crypto.getRandomValues(clientHelloHead.subarray(2, 2 + 32));

   // derived from _extensionList
   // NOTE only SignatureScheme 4,3,8,4,8,9 are succeed to decrypt smpt.gmail.com
   const extension_1 = Uint8Array.of(0, 10, 0, 4, 0, 2, 0, 29, 0, 13, 0, 14, 0, 12, 4,3,5,3,8,4,8,5,8,9,8,10, 0, 43, 0, 3, 2, 3, 4, 0, 45, 0, 2, 1, 1);
   // const extension_1 = Uint8Array.of(0, 10, 0, 4, 0, 2, 0, 29, 0, 13, 0, 4, 0, 2, 8, 4, /*8, 5, 8, 6, 8, 9, 8, 10, 8, 11, 4, 3, 5, 3, 6, 3, 8, 7, 8, 8, */ 0, 43, 0, 3, 2, 3, 4, 0, 45, 0, 2, 1, 1); 

   const x25519 = NamedGroup.X25519;
   //const secp256 = NamedGroup.SECP256R1

   const key_share = Extension.create(
      ExtensionType.KEY_SHARE,
      KeyShareClientHello.fromKeyShareEntries(
         x25519.keyShareEntry(),
         //secp256.keyShareEntry()
      )
   )

   const sni = Extension.create(
      ExtensionType.SERVER_NAME,
      ServerNameList.fromName(...serverNames)
   );

   const exts = safeuint8array(extension_1, sni, key_share);

   const extensions = safeuint8array(Uint16.fromValue(exts.length), exts);

   const clientHello = ClientHello.from(safeuint8array(clientHelloHead, extensions))
   clientHello.namedGroup = x25519
   return clientHello
}