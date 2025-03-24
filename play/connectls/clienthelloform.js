import { ClientHello, Extension, ExtensionType, KeyShareClientHello, NamedGroup, PskKeyExchangeMode, safeuint8array, ServerNameList, SignatureScheme, Uint16 } from "../../src/dep.ts";

export function clientHelloForm(...serverNames) {
   const x25519 = NamedGroup.X25519;
   const p256 = NamedGroup.SECP256R1;
   const p384 = NamedGroup.SECP384R1;
   class ClientHelloForm {
      // ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
      #version = Uint8Array.of(3, 3);
      // opaque Random[32];
      #random = crypto.getRandomValues(new Uint8Array(32));
      // opaque legacy_session_id<0..32>;
      #sessionId = Uint8Array.of(0)//safeuint8array(32, crypto.getRandomValues(new Uint8Array(32)));//
      // CipherSuite cipher_suites<2..2^16-2>;
      // uint8 CipherSuite[2];    /* Cryptographic suite selector */
      #ciphers = Uint8Array.of(0, 6, 19, 1, 19, 2, 19, 3);
      // opaque legacy_compression_methods<1..2^8-1>;
      #compression = Uint8Array.of(1, 0);
      #extensions = new Map([
         [
            ExtensionType.SUPPORTED_GROUPS,
            safeuint8array(
               Uint8Array.of(0, 6),
               NamedGroup.X25519.byte,
               NamedGroup.SECP256R1.byte,
               NamedGroup.SECP384R1.byte,
            )
         ],
         [
            ExtensionType.SIGNATURE_ALGORITHMS,
            safeuint8array(
               Uint8Array.of(0, 12),
               SignatureScheme.ECDSA_SECP256R1_SHA256.byte,
               SignatureScheme.ECDSA_SECP384R1_SHA384.byte,
               SignatureScheme.RSA_PSS_RSAE_SHA256.byte,
               SignatureScheme.RSA_PSS_RSAE_SHA384.byte,
               SignatureScheme.RSA_PSS_PSS_SHA256.byte,
               SignatureScheme.RSA_PSS_PSS_SHA384.byte,
            )
         ],
         [
            ExtensionType.SUPPORTED_VERSIONS,
            Uint8Array.of(2, 3, 4/* , 3, 3 */)
         ],
         [
            ExtensionType.PSK_KEY_EXCHANGE_MODES,
            Uint8Array.of(1, +PskKeyExchangeMode.PSK_DHE_KE)
         ],
         /* [
            ExtensionType.EC_POINT_FORMATS,
            Uint8Array.of(3, 0, 1, 2)
         ] */
      ])
      #groups = new Map([
         [x25519, x25519],
         [p256, p256],
         [p384, p384]
      ])
      constructor(...serverNames) {
         this.#extensions.set(
            ExtensionType.SERVER_NAME,
            ServerNameList.fromName(...serverNames))
         this.init();
      }
      init() {
         this.#extensions.set(
            ExtensionType.KEY_SHARE,

            KeyShareClientHello.fromKeyShareEntries(
               this.#groups.get(NamedGroup.X25519).keyShareEntry(),
               /* this.#groups.get(NamedGroup.SECP256R1).keyShareEntry(),
               this.#groups.get(NamedGroup.SECP384R1).keyShareEntry(), */
            )
         )
      }
      get build() {
         const extensions = new Set
         let length = 0;
         for (const [key, value] of this.extensions) {
            const extension = Extension.create(key, value)
            extensions.add(extension);
            length += extension.length;
         }
         const clientHello = ClientHello.from(
            safeuint8array(
               this.version,
               this.random,
               this.sessionId,
               this.ciphers,
               this.compression,
               Uint16.fromValue(length),
               ...extensions
            ))
         clientHello.groups = this.#groups
         return clientHello;
      }
      get version() { return this.#version }
      get random() { return this.#random }
      get sessionId() { return this.#sessionId }
      get ciphers() { return this.#ciphers }
      get compression() { return this.#compression }
      get extensions() { return this.#extensions }
      get x25519() { return this.#groups.get(NamedGroup.X25519) }
      get p256() { return this.#groups.get(NamedGroup.SECP256R1) }
      get p384() { return this.#groups.get(NamedGroup.SECP384R1) }
      get groups() { return this.#groups }
      updateNamedGroup(group) {
         this.#groups.set(group, group)
         this.#extensions.set(
            ExtensionType.KEY_SHARE,
            KeyShareClientHello.fromKeyShareEntries(
               group.keyShareEntry(),
            )
         )
      }
   }
   return new ClientHelloForm(...serverNames)
}