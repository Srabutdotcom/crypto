//@ts-self-types="../../type/keyschedule/keyschedule.d.ts"
import { hkdf, Uint16 } from "../dep.ts";
import { Struct, Constrained, sha256, sha384 } from "../dep.ts";

export function derivedSecret(secret, label, messages = new Uint8Array, hashLength) {
   //const hashByteLength = secret.length;
   let hash = undefined
   switch (hashLength) {
      case 32: hash = sha256; break;
      case 48: hash = sha384; break;
   }
   const context = hash
      .create()
      .update(Uint8Array.from(messages))
      .digest()
   return hkdfExpandLabel(secret, label, context, hashLength)
}

export function hkdfExpandLabel(secret, label, context, Length) {
   switch (secret.length) {
      case 32: return hkdf.expand(sha256, secret, Uint8Array.from(HkdfLabel.of(Length, label, context)), Length)
      case 48: return hkdf.expand(sha384, secret, Uint8Array.from(HkdfLabel.of(Length, label, context)), Length)
   }
}

class HkdfLabel extends Struct {
   static of(Length, label, context) { return new HkdfLabel(Length, label, context) }
   constructor(Length, label, context) {
      super(
         Uint16.fromValue(Length),
         Label.of(label),
         Context.of(context)
      )
   }
}

class Label extends Constrained {
   static of(label) { return new Label(label) }
   constructor(label) {
      super(7, 255, new TextEncoder().encode(`tls13 ${label}`))
   }
}

class Context extends Constrained {
   static of(context) { return new Context(context) }
   constructor(context) {
      super(0, 255, context)
   }
}

export class DerivedSecret {
   static SHA256 = Uint8Array.of(111, 38, 21, 161, 8, 199, 2, 197, 103, 143, 84, 252, 157, 186, 182, 151, 22, 192, 118, 24, 156, 72, 37, 12, 235, 234, 195, 87, 108, 54, 17, 186);
   static SHA384 = Uint8Array.of(21,145,218,197,203,191,3,48,164,168,77,233,199,83,51,14,146,208,31,10,136,33,75,68,100,151,47,214,104,4,158,147,229,47,43,22,250,217,34,253,192,88,68,120,66,143,40,43);
}

export function finishedKey(serverHS_secret, hashLength) {
   return hkdfExpandLabel(serverHS_secret, 'finished', new Uint8Array, hashLength ?? serverHS_secret.length);
}


//TODO: 
/* 
HKDF-Expand-Label(Secret, Label, Context, Length) =
HKDF-Expand(Secret, HkdfLabel, Length) 

Where HkdfLabel is specified as:

struct {
   uint16 length = Length;
   opaque label<7..255> = "tls13 " + Label;
   opaque context<0..255> = Context;
} HkdfLabel;

Derive-Secret(Secret, Label, Messages) =
   HKDF-Expand-Label(Secret, Label,
                     Transcript-Hash(Messages), Hash.length)
*/