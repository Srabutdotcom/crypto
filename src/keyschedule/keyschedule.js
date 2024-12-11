//@ts-self-types="../../type/keyschedule/keyschedule.d.ts"
import { hkdf, Uint16 } from "../dep.ts";
import { Struct, Constrained, sha256, sha384 } from "../dep.ts";

export function derivedSecret(secret, label, messages = new Uint8Array){
   const hashByteLength = secret.length;
   let hash = undefined
   switch (hashByteLength) {
      case 32: hash = sha256; break;
      case 48: hash = sha256; break;
   }
   const context = hash
      .create()
      .update(Uint8Array.from(messages))
      .digest()
   return hkdfExpandLabel(secret, label, context, hashByteLength) 
}

export function hkdfExpandLabel(secret, label, context, Length){
   switch (Length) {
      case 32: return hkdf.expand(sha256, secret, Uint8Array.from(HkdfLabel.of(Length, label, context)), Length)
      case 48: return hkdf.expand(sha384, secret, Uint8Array.from(HkdfLabel.of(Length, label, context)), Length)
   }
}

class HkdfLabel extends Struct {
   static of(Length, label, context){return new HkdfLabel(Length, label, context)}
   constructor(Length, label, context){
      super(
         Uint16.fromValue(Length),
         Label.of(label),
         Context.of(context)
      )
   }
}

class Label extends Constrained {
   static of(label){ return new Label(label)}
   constructor(label){
      super(7, 255, new TextEncoder().encode(`tls13 ${label}`))
   }
}

class Context extends Constrained {
   static of(context){ return new Context(context)}
   constructor(context){
      super(0, 255, context)
   }
}

export class DerivedSecret {
   static SHA256 = Uint8Array.of(111,38,21,161,8,199,2,197,103,143,84,252,157,186,182,151,22,192,118,24,156,72,37,12,235,234,195,87,108,54,17,186);
   static SHA384 =  Uint8Array.of(115,123,52,69,75,237,139,131,80,43,54,16,80,167,99,154,146,146,198,59,140,7,137,209,122,146,113,108,234,67,141,183,30,88,208,165,51,240,17,149,152,60,244,110,133,34,78,95);
}

export function finishedKey(serverHS_secret, hashLength){
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