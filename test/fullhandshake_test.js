import { HandshakeKey, HandshakeRole, ApplicationKey } from "../src/secret/fullhandshake.js";
import { clientHello, clientPrivateKey } from "./data_fullhandshake/fullhandshake_data.js";
import { serverHello, response } from "./data_fullhandshake/fullhandshake_data.js";
import { AlertDescription, ClientHello, ContentType, Handshake, HandshakeType, NamedGroup, 
   ServerHello, verifyCertificateVerify } from "../src/dep.ts";
import { TLSCiphertext, parseItems } from "../src/dep.ts";
import { EncryptedExtensions, Certificate, CertificateVerify, Finished } from "../src/dep.ts";
import { Transcript } from "../src/secret/transcript.js"
import { parseHandshakes, parseRecords } from "../play/connectls/parserecord.js"
import { verifyFinished, createFinished } from "../src/finish/finish.js"
/**
 * Handshake simulation from Client Hello to Smtp server
 * 1. Preparing and send ClientHello
 *    - store client private key
 *    - wrap clientHello to ClientHello class
 *    - store clientHello message (handshake) to transcript for later use
 */

const clientHello_0 = ClientHello.from(clientHello)
clientHello_0.groups = new Map([
   [ NamedGroup.X25519, { privateKey: clientPrivateKey } ]
])
const transcript = new Transcript(clientHello_0.handshake)

/**!SECTION
 * 2. Receive response from smtp server
 *    Possible value are (1). Undefined, (2). Alert, or (3). Handshakes 
 *    - We have to extract each record
 *    - insert serverHello message (handshake) to transcript
 *    - generate handshake key
 *    - decrypt application data, in this case no helloRetryRequest
 */
if (ContentType.from(response) == ContentType.ALERT) {
   throw Error(AlertDescription.BAD_RECORD_MAC.alert().description);
}
if (ContentType.from(response) !== ContentType.HANDSHAKE) {
   throw Error("Expected Handshake")
}

const records = parseRecords(response);
transcript.insert(records.get(ContentType.HANDSHAKE).fragment)

const handshakeKeys = new HandshakeKey(transcript);
const decryptedHandshake = handshakeKeys.aead_hs_s.open(records.get(ContentType.APPLICATION_DATA))
const handshakes = parseHandshakes(decryptedHandshake.content);
const encryptedExtsMsg = handshakes.get(HandshakeType.ENCRYPTED_EXTENSIONS);
transcript.insert(encryptedExtsMsg);
const certificateMsg = handshakes.get(HandshakeType.CERTIFICATE);
// verify certificate
const _isCertificateValid = await certificateMsg.message.verify();
transcript.insert(certificateMsg);
// verify certificateVerify
const certificateVerifyMsg = handshakes.get(HandshakeType.CERTIFICATE_VERIFY);
const _isCertificateVerifyValid = await verifyCertificateVerify(transcript, certificateVerifyMsg)
// verify finishedMsg 
const finishedMsg = handshakes.get(HandshakeType.FINISHED)
const _isFinishedValid = await verifyFinished(handshakeKeys.finished_key_s, transcript, finishedMsg) 

/**!SECTION
 * 3. Generate Application keys
 *    - create finishedClientMsg
 *    - generate record of finishedClientMsg (encrypted using hs_server key)
 */

const appKey = new ApplicationKey(handshakeKeys, transcript);
const finishedClientMsg = await createFinished(handshakeKeys.finished_key_c, transcript);
const finishRecordEncrypted = handshakeKeys.aead_hs_c.seal(finishedClientMsg, ContentType.HANDSHAKE);

