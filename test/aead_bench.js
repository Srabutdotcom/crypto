import { ChaCha20Poly1305, HexaDecimal } from "../src/dep.ts";
import { AES } from "@stablelib/aes";
import { GCM } from "@stablelib/gcm"
import { gcm } from "@noble/ciphers/aes"

const key = HexaDecimal.fromString("5394E890D37BA55EC9D5F327F15680F6A63EF5279C79331643AD0AF6D2623525");
const nonce = HexaDecimal.fromString("815E840B7ACA7AF3B324583F");
const plaintext = HexaDecimal.fromString(
   "8E63067CD15359F796B43C68F093F55FDF3589FC5F2FDFAD5F9D156668A6" +
   "17F7091D73DA71CDD207810E6F71A165D0809A597DF9885CA6E8F9BB4E61" +
   "6166586B83CC45F49917FC1A256B8BC7D05C476AB5C4633E20092619C474" +
   "7B26DAD3915E9FD65238EE4E5213BADEDA8A3A22F5EFE6582D0762532026" +
   "C89B4CA26FDD000EB45347A2A199B55B7790E6B1B2DBA19833CE9F9522C0" +
   "BCEA5B088CCAE68DD99AE0203C81B9F1DD3181C3E2339E83CCD1526B6774" +
   "2B235E872BEA5111772AAB574AE7D904D9B6355A79178E179B5AE8EDC54F" +
   "61F172BF789EA9C9AF21F45B783E4251421B077776808F04972A5E801723" +
   "CF781442378CE0E0568F014AEA7A882DCBCB48D342BE53D1C2EBFB206B12" +
   "443A8A587CC1E55CA23BECA385D61D0D03E9D84CBC1B0A"
)
const ad = HexaDecimal.fromString("0FECCDFAE8ED65FA31A0858A1C466F79E8AA658C2F3BA93C3F92158B4E30955E1C62580450BEFF");
const result = HexaDecimal.fromString(
   "B69A7E17BB5AF688883274550A4DED0D1AFF49A0B18343F4B382F745C163" +
   "F7F714C9206A32A1FF012427E19431951EDD0A755E5F491B0EEDFD7DF68B" +
   "BC6085DD2888607A2F998C3E881EB1694109250DB28291E71F4AD344A125" +
   "624FB92E16EA9815047CD1111CABFDC9CB8C3B4B0F40AA91D31774009781" +
   "231400789ED545404AF6C3F76D07DDC984A7BD8F52728159782832E298CC" +
   "4D529BE96D17BE898EFD83E44DC7B0E2EFC645849FD2BBA61FEF0AE7BE0D" +
   "CAB233CC4E2B7BA4E887DE9C64B97F2A1818AA54371A8D629DAE37975F77" +
   "84E5E3CC77055ED6E975B1E5F55E6BBACDC9F295CE4ADA2C16113CD5B323" +
   "CF78B7DDE39F4A87AA8C141A31174E3584CCBD380CF5EC6D1DBA539928B0" +
   "84FA9683E9C0953ACF47CC3AC384A2C38914F1DA01FB2CFD78905C2B58D3" +
   "6B2574B9DF15535D82"
)

Deno.bench("AES-GCM using stablelib", () => {
   const cipher = new AES(key.byte)
   const gcm = new GCM(cipher);

   const sealed = gcm.seal(nonce.byte, plaintext.byte, ad.byte);
   const open = gcm.open(nonce.byte, result.byte, ad.byte)
})

Deno.bench("AES-GCM using webcrypto", async () => {
   //using web crypto
   const cryptoKey = await self.crypto.subtle.importKey('raw', key.byte, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'])
   const sealed_web = await self.crypto.subtle.encrypt({
      name: "AES-GCM",
      iv: nonce.byte,
      additionalData: ad.byte, // as additional data
      //tagLength: 128 //*by default is 128
   }, cryptoKey, plaintext.byte);

   const open_web = await self.crypto.subtle.decrypt({
      name: "AES-GCM",
      iv: nonce.byte,
      additionalData: ad.byte, // as additional data
      //tagLength: 128 //*by default is 128
   }, cryptoKey, sealed_web);

   const a = new Uint8Array(sealed_web);
   const b = new Uint8Array(open_web)
})

/* 
benchmark                 time/iter (avg)        iter/s      (min … max)           p75      p99     p995
------------------------- ----------------------------- --------------------- --------------------------
AES-GCM using stablelib          127.1 µs         7,869 (109.4 µs … 769.2 µs) 130.3 µs 198.8 µs 216.4 µs
AES-GCM using webcrypto          181.3 µs         5,517 (142.8 µs …   1.2 ms) 179.2 µs 312.4 µs 330.9 µs */


const cipher = new AES(key.byte)
const gcm_ = new GCM(cipher);

const sealed = gcm_.seal(nonce.byte, plaintext.byte, ad.byte);
const open = gcm_.open(nonce.byte, result.byte, ad.byte)

const cipherText = gcm(key.byte, ad.byte).encrypt(plaintext.byte);
const plainText = gcm(key.byte, ad.byte).decrypt(cipherText);

const cipherChacha20 = new ChaCha20Poly1305(key.byte);
//const gcmChacha20 = new GCM(cipherChacha20);

const sealedChacha20 = cipherChacha20.seal(nonce.byte, plaintext.byte, ad.byte);
const openChacha20 = cipherChacha20.open(nonce.byte, sealedChacha20, ad.byte)

const n = null;